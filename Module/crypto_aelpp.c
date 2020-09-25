/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * xxxxxxxx - Pedro
 */

#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/mutex.h>	         /// Required for the mutex functionality
#include <linux/scatterlist.h>
#include <asm/uaccess.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#define SYMMETRIC_KEY_LENGTH 32
#define CIPHER_BLOCK_SIZE 16
#define  DEVICE_NAME "crypto_aelpp"    ///< The device will appear at  using this value
#define  CLASS_NAME  "cpt_aelpp"        ///< The device class -- this is a character device driver
#define ENCRYPT   0
#define DECRYPT   1
#define SHA1_LENGTH (40)
#define SHA256_LENGTH (256/8)
#define DATA_SIZE       16
#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)
MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Agostinho Sanches/Evandro Capovilla/Lucas Tenani/Pedro Caccavaro/Pedro Catalini");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux crypt driver");  ///< The description -- see modinfo
MODULE_VERSION("1.0");            ///< A version number to inform users


static int    majorNumber;                  ///< Stores the device number
static char   message[256] = {0};           ///< Memory for the string that
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer
static char *iv = "blah";
static char *key = "blah";

static int makeHash(char *data);

static int makeEncryptOrDecrypt(char* input, int action)

static void hexdump(unsigned char *buf, unsigned int len);

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);



static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

struct tcrypt_result 
{
 struct completion completion;
 int err;
};
struct skcipher_def 
{
   struct scatterlist sg;
   struct crypto_skcipher * tfm;
   struct skcipher_request * req;
   struct tcrypt_result result;
   char * scratchpad;
   char * ciphertext;
   char * ivdata;
};
static struct skcipher_def sk;


static DEFINE_MUTEX(ebbchar_mutex);


module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Initialization Vector");
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Key to AES");


static int __init crypto_aelpp_init(void){
   printk(KERN_INFO "Crypto_aelpp: Initializing the Crypto\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "Crypto_aelpp failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "Crypto_aelpp: registered correctly with major number %d\n", majorNumber);
   printk(KERN_INFO "Crypto_aelpp: Key is: %s\n", key);
   printk(KERN_INFO "Crypto_aelpp: IV is: %s\n", iv);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "Crypto_aelpp: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   printk(KERN_INFO "Crypto_aelpp: Initializing mutex \n"); // Mutex initialization
   mutex_init(&ebbchar_mutex);
   printk(KERN_INFO "Crypto_aelpp: Mutex created! \n"); // Mutex OK

   printk(KERN_INFO "Crypto_aelpp: device class created correctly\n"); // Made it! device was initialized
   return 0;
}


static void __exit crypto_aelpp_exit(void){
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   mutex_destroy(&ebbchar_mutex);                           // destroy the dynamically-allocated mutex
   printk(KERN_INFO "Crypto_aelpp: Goodbye from the LKM!\n");
}




static int dev_open(struct inode *inodep, struct file *filep){
    if(!mutex_trylock(&ebbchar_mutex)){    /// Try to acquire the mutex returns 1 successful and 0
      printk(KERN_ALERT "Crypto_aelpp: Device in use by another process");
      return -EBUSY;
   }
   numberOpens++;
   printk(KERN_INFO "Crypto_aelpp: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}


static int makeHash(char *data){
	char * plaintext = data;
	char hash_sha1[SHA1_LENGTH];
	struct crypto_shash *sha1;
	struct shash_desc *shash;
	int i;
	char str[SHA1_LENGTH*2 + 1];

	sha1 = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(sha1)){
		printk(KERN_INFO "Crypto_aelpp: Fail alloc_shash\n");
		return -1;
	}

	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha1),GFP_KERNEL);
	if (!shash){
		printk(KERN_INFO "Crypto_aelpp: Fail kmalloc\n");
		return -ENOMEM;
	}

	shash->tfm = sha1;
	shash->flags = 0;

	if(crypto_shash_init(shash)){
		printk(KERN_INFO "Crypto_aelpp: Fail shash_init\n");
		return -1;
	}

	if(crypto_shash_update(shash, plaintext, strlen(plaintext))){
		printk(KERN_INFO "Crypto_aelpp: Fail shash_update\n");
		return -1;
	}

	if(crypto_shash_final(shash, hash_sha1)){
		printk(KERN_INFO "Crypto_aelpp: Fail shash_final\n");
		return -1;
	}

	/*kfree(shash);
	crypto_free_shash(sha1);
	*/

	printk(KERN_INFO "Crypto_aelpp: sha1 Plaintext: %s\n", plaintext);
	for (i = 0; i < SHA256_LENGTH ; i++)
		sprintf(&str[i*2],"%02x", (unsigned char)hash_sha1[i]);
	str[i*2] = 0;
	printk(KERN_INFO "Crypto_aelpp: sha1 Result: %s\n", str);
	strncpy(message,str,strlen(str));
	size_of_message = strlen(str);
	return 0;
}


static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   char *data,operation;
   char space =' ';
   int ret;

   copy_from_user(message,buffer,len);
   operation = *message;
   data = strchr(message,space);
   data = data+1;
   printk(KERN_INFO "Crypto_aelpp: Received - Operation: %c Data: %s\n", operation, data);

   switch(operation){
		case 'c':
         ret = makeEncryptOrDecrypt(data, ENCRYPT);
			break;
		case 'd':
         ret = makeEncryptOrDecrypt(data, DECRYPT);
			break;
		case 'h':
			ret = makeHash(data);
			break;
	}

   return len;
}


static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "Crypto_aelpp: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "Crypto_aelpp: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

static void test_skcipher_finish(struct skcipher_def * sk)
{
   if (sk->tfm)
      crypto_free_skcipher(sk->tfm);
   if (sk->req)
      skcipher_request_free(sk->req);
   if (sk->ivdata)
      kfree(sk->ivdata);
   if (sk->scratchpad)
      kfree(sk->scratchpad);
   if (sk->ciphertext)
      kfree(sk->ciphertext);
}
static int test_skcipher_result(struct skcipher_def * sk, int rc)
{
   switch (rc) 
   {
      case 0:
      break;
      case -EINPROGRESS:
      case -EBUSY:
         rc = wait_for_completion_interruptible(
         &sk->result.completion);
      if (!rc && !sk->result.err) 
      {
         reinit_completion(&sk->result.completion);
         break;
      }
      default:
         printk(KERN_INFO "Crypto_aelpp: skcipher encrypt returned with %d result %d\n",
         rc, sk->result.err);
      break;
   }
   init_completion(&sk->result.completion);
   return rc;
}
static void test_skcipher_callback(struct crypto_async_request *req, int error)
{
   struct tcrypt_result *result = req->data;
   if (error == -EINPROGRESS)
      return;
   result->err = error;
   complete(&result->completion);
   printk(KERN_INFO "Crypto_aelpp: Request finished successfully\n");
}

static int makeEncryptOrDecrypt(char * input, int action)
{
   char * plaintext = input;
   char * password = key;

   sk.tfm = NULL;
   sk.req = NULL;
   sk.scratchpad = NULL;
   sk.ciphertext = NULL;
   sk.ivdata = iv;

   int ret = -1;
   unsigned char key[SYMMETRIC_KEY_LENGTH];
   if (!sk->tfm) 
   {
      sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
      if (IS_ERR(sk->tfm)) 
      {
         printk(KERN_INFO "Crypto_aelpp: could not allocate skcipher handle\n");
         return PTR_ERR(sk->tfm);
      }  
   }
   if (!sk->req) 
   {
      sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
      if (!sk->req) 
      {
         printk(KERN_INFO "Crypto_aelpp: could not allocate skcipher request\n");
         ret = -1;
         goto out;
      }
   }
   skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_callback, &sk->result);
   /* clear the key */
   memset((void*)key,'\0', SYMMETRIC_KEY_LENGTH);

   sprintf((char*)key,"%s",password);

   /* AES 256 with given symmetric key */
   if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) 
   {
      printk(KERN_INFO "Crypto_aelpp: key could not be set\n");
      ret = -1;
      goto out;
   }
   printk(KERN_INFO "Crypto_aelpp: Symmetric key: %s\n", key);
   printk(KERN_INFO "Crypto_aelpp: Plaintext: %s\n", plaintext);
   if (!sk->ivdata) 
   {
      /* see https://en.wikipedia.org/wiki/Initialization_vector */
      sk->ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
      if (!sk->ivdata) 
      {
         printk(KERN_INFO "Crypto_aelpp: could not allocate ivdata\n");
         goto out;
      }
      get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
   }
   if (!sk->scratchpad) 
   {
      /* The text to be encrypted */
      sk->scratchpad = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
      if (!sk->scratchpad) 
      {
         printk(KERN_INFO "Crypto_aelpp: could not allocate scratchpad\n");
         goto out;
      }
   }
   sprintf((char*)sk->scratchpad,"%s",plaintext);
   sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE);
   skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE, sk->ivdata);

   init_completion(&sk->result.completion);

   switch(action)
   {
      case ENCRYPT:
         ret = crypto_skcipher_encrypt(sk->req);
         ret = test_skcipher_result(sk, ret);
         if (ret)
            printk(KERN_INFO "Crypto_aelpp: Encryption request successful\n \n");
         return ret;

      case DECRYPT:
         ret = crypto_skcipher_decrypt(sk->req);
         ret = test_skcipher_result(sk, ret);
         if (ret)
            printk(KERN_INFO "Crypto_aelpp: Decryption request successful\n \n");
         return ret;

      default:
         return -1;

   }
}

static int dev_release(struct inode *inodep, struct file *filep){
   mutex_unlock(&ebbchar_mutex);                      // Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "Crypto_aelpp: Device successfully closed\n");
   return 0;
}



module_init(crypto_aelpp_init);
module_exit(crypto_aelpp_exit);
