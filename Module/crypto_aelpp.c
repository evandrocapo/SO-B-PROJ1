/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * xxxxxxxx - Lucas
 * xxxxxxxx - Pedro Caccavaro
 * xxxxxxxx - Pedro
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

#define DEVICE_NAME "crypto_aelpp" ///< The device will appear at  using this value
#define CLASS_NAME "cpt_aelpp"     ///< The device class -- this is a character device driver
#define SHA1_LENGTH (40)
#define SHA256_LENGTH (256 / 8)
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

static char *iv = "0123456789abcdef";
static char *key = "0123456789abcdef";
size_t ivsize;

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

   /*kfree(shash);
	crypto_free_shash(sha1);
	*/

   printk(KERN_INFO "Crypto_aelpp: sha1 Plaintext: %s\n", plaintext);
   for (i = 0; i < SHA256_LENGTH; i++)
      sprintf(&str[i * 2], "%02x", (unsigned char)hash_sha1[i]);
   str[i * 2] = 0;
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
      // rc = crypto_skcipher_decrypt(sk->req);

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

static int criptografar(char *data)
{
   char * plaintext = NULL;
   char * ponteiro_do_iv;
   char ciphertext[16] = {0};
   char keyzada[16] = "0123456789abcdef";
   char ivzada[16] = "0123456789abcdef";
   int err;

   plaintext = kmalloc(16, GFP_KERNEL);
    if (!plaintext) {
        printk(KERN_INFO "Crypto_aelpp: could not allocate plaintext\n");
        goto error0;
    }

   tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_INFO "Crypto_aelpp: impossible to allocate skcipher\n");
        return PTR_ERR(tfm);
    }

   /* Default function to set the key for the symetric key cipher */
    err = crypto_skcipher_setkey(tfm, keyzada, sizeof(keyzada));
    if (err) {
        pr_err(KERN_INFO "Crypto_aelpp: fail setting key for transformation: %d\n", err);
        goto error0;
    }
    print_hex_dump(KERN_DEBUG, "Crypto_aelpp: key: ", DUMP_PREFIX_NONE, 16, 1, keyzada, 16,
               false);

   /* Each crypto cipher has its own Initialization Vector (IV) size,
     * because of that I first request the correct size for salsa20 IV and
     * then set it. Considering this is just an example I'll use as IV the
     * content of a random memory space which I just allocated. */
    ivsize = crypto_skcipher_ivsize(tfm);
    ponteiro_do_iv = kmalloc(ivsize, GFP_KERNEL);
    if (!ponteiro_do_iv) {
        printk(KERN_INFO "Crypto_aelpp: could not allocate iv vector\n");
        err = -ENOMEM;
        goto error0;
    }

   //  memcpy(ponteiro_do_iv, "0123456789abcdef", 16);
    print_hex_dump(KERN_DEBUG, "Crypto_aelpp: ponteiro_do_iv: ", DUMP_PREFIX_NONE, 16, 1, ivzada,
               ivsize, false);

    /* Requests are objects that hold all information about a crypto
     * operation, from the tfm itself to the buffers and IV that will be
     * used in the enc/decryption operations. But it also holds
     * information about asynchronous calls to the crypto engine. If we
     * have chosen async calls instead of sync ones, we should also set
     * the callback function and some other flags in the request object in
     * order to be able to receive the output date from each operation
     * finished. */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_INFO "Crypto_aelpp: impossible to allocate skcipher request\n");
        err = -ENOMEM;
        goto error0;
    }

    /* The word to be encrypted */
    /* TODO: explain scatter/gather lists, that has relation to DMA */
    memcpy(plaintext, data, sizeof(data));

    sg_init_one(&sg, plaintext, 16);
    skcipher_request_set_crypt(req, &sg, &sg, 16, ivzada);

    print_hex_dump(KERN_DEBUG, "Crypto_aelpp: orig text: ", DUMP_PREFIX_NONE, 16, 1,
               plaintext, 16, true);

    /* Encrypt operation against "plaintext" content */
    err = crypto_skcipher_encrypt(req);

    if (err) {
        printk(KERN_INFO "Crypto_aelpp: could not encrypt data\n");
        goto error1;
    }

    sg_copy_to_buffer(&sg, 1, ciphertext, 16);
    print_hex_dump(KERN_DEBUG, "encr text: ", DUMP_PREFIX_NONE, 16, 1,
               ciphertext, 16, true);


   memcpy(message, ciphertext, 16);
   size_of_message = strnlen_user(ciphertext, 16);
   message[16] = '\0';

   printk(KERN_INFO "Crypto_aelpp: cifrado: %s\n", message);

   error1:
    skcipher_request_free(req);
   error2:
    kfree(plaintext);
   error0:
    crypto_free_skcipher(tfm);
    return err;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
   char *data, operation;
   char space = ' ';
   int ret;

   copy_from_user(message, buffer, len);
   operation = *message;
   data = strchr(message, space);
   data = data + 1;
   printk(KERN_INFO "Crypto_aelpp: Received - Operation: %c Data: %s\n", operation, data);

   switch (operation)
   {
   case 'c':
      printk(KERN_INFO "Crypto_aelpp: Lets cipher\n");
      ret = criptografar(data);
      break;
   case 'd':
      printk(KERN_INFO "Crypto_aelpp: Lets decipher\n");
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
