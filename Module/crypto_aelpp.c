/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * 15248354 - Pedro Angelo Catalini
 */

#include <linux/init.h>    // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>  // Core header for loading LKMs into the kernel
#include <linux/device.h>  // Header to support the kernel Driver Model
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/mutex.h>   /// Required for the mutex functionality
#include <linux/scatterlist.h>
#include <asm/uaccess.h> // é necessario ?
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h> // é necessario ?
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/string.h>

#define DEVICE_NAME "crypto_aelpp" ///< The device will appear at  using this value
#define CLASS_NAME "cpt_aelpp"     ///< The device class -- this is a character device driver
#define SHA1_LENGTH (40)
#define SHA256_LENGTH (256 / 8)
#define AES_BLOCK_SIZE 16
MODULE_LICENSE("GPL");                                                                            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Agostinho Sanches/Evandro Capovilla/Lucas Tenani/Pedro Caccavaro/Pedro Catalini"); ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux crypt driver");                                                ///< The description -- see modinfo
MODULE_VERSION("1.0");                                                                            ///< A version number to inform users

static int majorNumber;                     ///< Stores the device number
static char message[256] = {0};             ///< Memory for the string that
static short size_of_message;               ///< Used to remember the size of the string stored
static int numberOpens = 0;                 ///< Counts the number of times the device is opened
static struct class *ebbcharClass = NULL;   ///< The device-driver class struct pointer
static struct device *ebbcharDevice = NULL; ///< The device-driver device struct pointer

static int makeHash(char *data);
static int criptografar(char *data);

static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

struct crypto_skcipher *tfm;
struct skcipher_request *req = NULL;
struct scatterlist sg;

char *vetor[2];

static char *iv = "";
static char *key = "";
size_t ivsize;

void encrypt(char *buf);
static char *dest1;

// Struct
struct tcrypt_result
{
   struct completion completion;
   int err;
};
/* tie all data structures together */
struct skcipher_def
{
   struct scatterlist sg;
   struct crypto_skcipher *tfm;
   struct skcipher_request *req;
   struct tcrypt_result result;
};

static struct file_operations fops =
    {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

static DEFINE_MUTEX(ebbchar_mutex);

module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Initialization Vector");
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Key to AES");

static int __init crypto_aelpp_init(void)
{
   printk(KERN_INFO "Crypto_aelpp: Initializing the Crypto\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber < 0)
   {
      printk(KERN_ALERT "Crypto_aelpp failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "Crypto_aelpp: registered correctly with major number %d\n", majorNumber);
   printk(KERN_INFO "Crypto_aelpp: Key is: %s\n", key);
   printk(KERN_INFO "Crypto_aelpp: IV is: %s\n", iv);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass))
   { // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass); // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "Crypto_aelpp: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice))
   {                               // Clean up if there is an error
      class_destroy(ebbcharClass); // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   printk(KERN_INFO "Crypto_aelpp: Initializing mutex \n"); // Mutex initialization
   mutex_init(&ebbchar_mutex);
   printk(KERN_INFO "Crypto_aelpp: Mutex created! \n"); // Mutex OK

   if (!crypto_has_skcipher("salsa20", 0, 0))
   {
      pr_err("skcipher not found\n");
      return -EINVAL;
   }

   printk(KERN_INFO "Crypto_aelpp: skcipher found ! :)");

   printk(KERN_INFO "Crypto_aelpp: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

static void __exit crypto_aelpp_exit(void)
{
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0)); // remove the device
   class_unregister(ebbcharClass);                      // unregister the device class
   class_destroy(ebbcharClass);                         // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
   mutex_destroy(&ebbchar_mutex);                       // destroy the dynamically-allocated mutex
   printk(KERN_INFO "Crypto_aelpp: Closing the module ! BYE ! :)\n");
}

static int dev_open(struct inode *inodep, struct file *filep)
{
   if (!mutex_trylock(&ebbchar_mutex))
   { /// Try to acquire the mutex returns 1 successful and 0
      printk(KERN_ALERT "Crypto_aelpp: Device in use by another process");
      return -EBUSY;
   }
   numberOpens++;
   printk(KERN_INFO "Crypto_aelpp: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

static int makeHash(char *data)
{
   char *plaintext = data;
   char hash_sha1[SHA1_LENGTH];
   struct crypto_shash *sha1;
   struct shash_desc *shash;
   int i;
   char str[SHA1_LENGTH * 2 + 1];

   sha1 = crypto_alloc_shash("sha1", 0, 0);
   if (IS_ERR(sha1))
   {
      printk(KERN_INFO "Crypto_aelpp: Fail alloc_shash\n");
      return -1;
   }

   shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha1), GFP_KERNEL);
   if (!shash)
   {
      printk(KERN_INFO "Crypto_aelpp: Fail kmalloc\n");
      return -ENOMEM;
   }

   shash->tfm = sha1;
   shash->flags = 0;

   if (crypto_shash_init(shash))
   {
      printk(KERN_INFO "Crypto_aelpp: Fail shash_init\n");
      return -1;
   }

   if (crypto_shash_update(shash, plaintext, strlen(plaintext)))
   {
      printk(KERN_INFO "Crypto_aelpp: Fail shash_update\n");
      return -1;
   }

   if (crypto_shash_final(shash, hash_sha1))
   {
      printk(KERN_INFO "Crypto_aelpp: Fail shash_final\n");
      return -1;
   }


   printk(KERN_INFO "Crypto_aelpp: sha1 Plaintext: %s\n", plaintext);
   for (i = 0; i < SHA1_LENGTH; i++)
      sprintf(&str[i * 2], "%02x", (unsigned char)hash_sha1[i]);
   str[i] = '\0';
   printk(KERN_INFO "Crypto_aelpp: sha1 Result: %s\n", str);
   strncpy(message, str, strlen(str));
   size_of_message = strlen(str);
   return 0;
}

static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
   struct tcrypt_result *result = req->data;

   if (error == -EINPROGRESS)
      return;
   result->err = error;
   complete(&result->completion);
   printk(KERN_INFO "Crypto_aelpp: Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                                         int enc)
{
   int rc = 0;

   if (enc)
      rc = crypto_skcipher_encrypt(sk->req);
   else

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



void encrypt(char *buf)  
{     
    printk(KERN_INFO "Encrypt function\n");
    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);
    char *buf2 = kmalloc (sizeof (char) * 256,GFP_KERNEL);


    int w=0, j=0;
    char* dest;
 
    printk("buf: %s", buf);
    printk("buf len: %i", strlen(buf));
    dest= buf1;
    struct crypto_cipher *tfm;
    int i,div=0,modd;  
    div=strlen(buf)/AES_BLOCK_SIZE;  
    modd=strlen(buf)%AES_BLOCK_SIZE; 
    printk("MOD: %i", modd); 
    if(modd>0)  
        div++; 
    printk("DIV: %i", div); 
    tfm=crypto_alloc_cipher("aes", 0, 16); 
    printk("POS CRYPTO");   
    crypto_cipher_setkey(tfm,key,16);    
    printk("CRYPTO CIPHER SETKEY");

    for(i=0;i<div;i++)  
    {  
        printk("FOR: %i", i);
        crypto_cipher_encrypt_one(tfm,buf1,buf);
        buf1 = buf1 + AES_BLOCK_SIZE; // TODO rever
        buf=buf+AES_BLOCK_SIZE;  
    }
    printk("POS FOR");
    crypto_free_cipher(tfm); 

    printk("Cifrado sem hexa: %s", dest);
    printk("w: %i", strlen(dest)); 

    for(w=0,j=0; w<strlen(dest); w++,j+=2)
	sprintf((char *)buf2+j,"%02x",dest[w]);

    buf2[j] = '\0';
    
    vetor[0] = dest;
    vetor[1] = buf2;

    printk("vetor 0 %s", vetor[0]);
    printk("vetor 1 %s", vetor[1]);
}

void decrypt(char *buf)
{  
    if( strcmp(buf, vetor[1]) == 0){
  
	    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);
	    
	    dest1 = buf1;
	  
	    struct crypto_cipher *tfm;  
	    int i,div,modd,offset;  
	    div=strlen(buf)/AES_BLOCK_SIZE;  
	    modd=strlen(buf)%AES_BLOCK_SIZE;  
	    if(modd>0)  
		div++;  

	    tfm=crypto_alloc_cipher("aes", 0, 16);  
	    crypto_cipher_setkey(tfm,key,16);  
	    for(i=0;i<div;i++)  
	    {  
	    	printk("FOR: %i", i);
		crypto_cipher_decrypt_one(tfm,buf1,vetor[0]); 
		buf1 = buf1 +  AES_BLOCK_SIZE;
		vetor[0]=vetor[0]+AES_BLOCK_SIZE;
		offset = offset + 8;
	    }
	 dest1[offset] = '\0';
	    printk("Decifrado: %s", dest1);
	}
}  

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
   char *data, operation;
   char space = ' ';
   int ret;

   strncpy(message, buffer, len);
   message[len] = '\0';
   printk(KERN_INFO "###### message %s ######\n", message);
   operation = *message;
   data = strchr(message, space);
   data = data + 1;
   printk(KERN_INFO "Crypto_aelpp: Received - Operation: %c Data: %s\n", operation, data);

   switch (operation)
   {
   case 'c':
      printk(KERN_INFO "Crypto_aelpp: Lets cipher MY VERSION 3\n");
      encrypt(data);
      printk("Dados anteriores: %s | Dados cifrados: %s",data,vetor[1]);
      strncpy(message, vetor[1], strlen(vetor[1]));
      size_of_message = strlen(vetor[1]);
      printk(KERN_INFO "size len %i\n",size_of_message);
      //ret = criptografar(data);
      break;
   case 'd':
      printk(KERN_INFO "Crypto_aelpp: Lets decipher 2\n");
      decrypt(data);
      strncpy(message, dest1, strlen(dest1));
      size_of_message = strlen(dest1);
      printk(KERN_INFO "size len %i\n",size_of_message);
      break;
   case 'h':
      printk(KERN_INFO "Crypto_aelpp: Lets hash\n");
      ret = makeHash(data);
      break;
   }

   return len;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count == 0)
   { // if true then have success
      printk(KERN_INFO "Crypto_aelpp: Sent %d characters to the user\n", size_of_message);
      return (size_of_message = 0); // clear the position to the start and return 0
   }
   else
   {
      printk(KERN_INFO "Crypto_aelpp: Failed to send %d characters to the user\n", error_count);
      return -EFAULT; // Failed -- return a bad address message (i.e. -14)
   }
}

static int dev_release(struct inode *inodep, struct file *filep)
{
   mutex_unlock(&ebbchar_mutex); // Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "Crypto_aelpp: Device successfully closed\n");
   return 0;
}

module_init(crypto_aelpp_init);
module_exit(crypto_aelpp_exit);
