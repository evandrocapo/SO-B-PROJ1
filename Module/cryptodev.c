#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#define  DEVICE_NAME "crypto"     ///< The device will appear at /dev/crypto using this value
#define  CLASS_NAME  "cryptodev"  ///< The device class -- this is a character device driver
#define AES_BLOCK_SIZE 16

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Grupo");    		  ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux cryptographic device driver");  ///< The description -- see modinfo
MODULE_VERSION("0.1");            ///< A version number to inform users

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  cryptoDevClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptoCharDevice = NULL; ///< The device-driver device struct pointer
char *vetor[2];
static char *dest1;
int flag = 0;

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static char* key;		//Variavel para receber a chave simetrica como parametro
void cifrar(char dados[256]);
void encrypt(char *buf);
void decifrar(char dados[256]);
char* calcular_hash(char dados[256]);

module_param(key, charp, 0000);		//pega a chave simetrica como parametro

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

/** @brief The initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */

static int __init cryptodev_init(void){
   printk(KERN_INFO "CryptoDevice: Inicializando o modulo de cryptografia ... \n");
   printk(KERN_INFO "CryptoDevice: Key = %s",key);

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "Falha para registrar o major number do CryptoDevice\n");
      return majorNumber;
   }
   printk(KERN_INFO "CryptoDevice: Registrado com sucesso com major number %d\n", majorNumber);

   // Register the device class
   cryptoDevClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptoDevClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Falha para registrar a classe do dispositivo \n");
      return PTR_ERR(cryptoDevClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "CryptoDevice: Classe do dispositivo registrada com sucesso \n");

   // Register the device driver
   cryptoCharDevice = device_create(cryptoDevClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptoCharDevice)){               // Clean up if there is an error
      class_destroy(cryptoDevClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Falha para criar o dispositivo \n");
      return PTR_ERR(cryptoCharDevice);
   }
   printk(KERN_INFO "CryptoDevice: Classe do dispositivo criada com sucesso \n"); // Made it! device was initialized
   return 0;
}

/** @brief The cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit cryptodev_exit(void){
   device_destroy(cryptoDevClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptoDevClass);                          // unregister the device class
   class_destroy(cryptoDevClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "CryptoDevice: Desregistrando o modulo ...\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "CryptoDevice: O dispositivo foi aberto %d vez(es)\n", numberOpens);
   return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "CryptoDevice: Enviados %d caracteres ao usuario \n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "CryptoDevice: Falha para enviar %d caracteres ao usuario \n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   
   int i;
   char operacao;
   char dados[strlen(buffer)];
   char resultado[256]=""; //verificar o tamanho necessario para o resultado
   char *hash_code;

   printk(KERN_INFO "CryptoDevice: Recebeu %zu caracteres do usuario \n", len);

   operacao = buffer[0];	//operacao: c, d ou h (cifrar, decifrar ou hash)

   for(i=1; i <= strlen(buffer); i++)
   {
      dados[i-1] = buffer[i]; //copia os dados para DADOS (copia tudo exceto a operacao)
   }

   if(operacao == 'c')
   {
      cifrar(dados);
      sprintf(message, "Dados anteriores: %s | Dados cifrados: %s | Chave utilizada: %s",dados,vetor[1],key);
      size_of_message = strlen(message);
   }

   else if(operacao == 'd')
   {
      decifrar(dados);

      if(flag == 0)
      {
      	sprintf(message, "Dados anteriores: %s | Dados decifrados: %s | Chave utilizada: %s",dados,dest1,key);
      }

      else
      {
	sprintf(message, "Codigo em hexadecimal invalido");
      }
      	size_of_message = strlen(message);     
   }

   else if(operacao == 'h')
   {
      hash_code = calcular_hash(dados);

      sprintf(message, "Dados: %s | Resumo Criptografico (HASH): %s",dados,hash_code);
      size_of_message = strlen(message);
      kfree(hash_code);
   }
   
   else
   {
      sprintf(message, "Esta operacao nao eh conhecida. \n");
      return -1;
   }


   printk(KERN_INFO "CryptoDevice: Dados recebidos -> Operacao: %c Dados: %s \n",operacao, dados);

   return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "CryptoDevice: Dispositivo fechado com sucesso \n");
   return 0;
}

void encrypt(char *buf)  
{     
    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);
    char *buf2 = kmalloc (sizeof (char) * 256,GFP_KERNEL);


    int w=0, j=0;
    char* dest;
 
    printk("buf: %s", buf);
    dest= buf1;
    struct crypto_cipher *tfm;  
    int i,count,div=0,modd;  
    div=strlen(buf)/AES_BLOCK_SIZE;  
    modd=strlen(buf)%AES_BLOCK_SIZE; 
    printk("MOD: %i", modd); 
    if(modd>0)  
        div++; 
    printk("DIV: %i", div); 
    count=div;  
    tfm=crypto_alloc_cipher("aes", 0, 16); 
    printk("POS CRYPTO");   
    crypto_cipher_setkey(tfm,key,16);    
    printk("CRYPTO CIPHER SETKEY");
    for(i=0;i<count;i++)  
    {  
	printk("ENTROU FOR");
        crypto_cipher_encrypt_one(tfm,dest,buf);
        printk("vez FOR: %i", i);      
        buf=buf+AES_BLOCK_SIZE;  
    }
    printk("POS FOR");
    crypto_free_cipher(tfm); 

    printk("Cifrado sem hexa: %s", dest); 

    
    for(w=0,j=0; w<strlen(dest); w++,j+=2)
    {
	sprintf((char *)buf2+j,"%02x",dest[w]);

    }

    buf2[j] = '\0';
    
    vetor[0] = dest;
    vetor[1] = buf2;

    printk("Teste vetor %s  %s ", vetor[0], vetor[1]);
    printk("Cifrado em Hexa: %s", buf2);

}


void decrypt(char *buf)
{  
    if( strcmp(buf, vetor[1]) == 0){
    
	    flag = 0;	  
	    char *buf1 = kmalloc (sizeof (char) * 256,GFP_KERNEL);
	    
	    dest1 = buf1;
	    
	  
	    struct crypto_cipher *tfm;  
	    int i,count,div,modd;  
	    div=strlen(buf)/AES_BLOCK_SIZE;  
	    modd=strlen(buf)%AES_BLOCK_SIZE;  
	    if(modd>0)  
		div++;  
	    count=div;  


	    tfm=crypto_alloc_cipher("aes", 0, 16);  
	    crypto_cipher_setkey(tfm,key,16);  
	    for(i=0;i<count;i++)  
	    {  
		crypto_cipher_decrypt_one(tfm,dest1,vetor[0]);   
		buf=buf+AES_BLOCK_SIZE;  
	    } 

	     
	    printk("Decifrado: %s", dest1);
	}else{	
		flag = 1;
		printk("Dados diferentes!!");
		//module_exit(cryptodev_exit);

	}
}  

void cifrar(char dados[256])
{
   encrypt(dados);
}


void decifrar(char dados[256])
{
   decrypt(dados);
   
   printk("Cryptodev: Chave recebida para decifrar: %s",key);
   
}

static int calc_hash(struct crypto_shash *alg,
                 const unsigned char *data, unsigned int datalen,
                 unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);

    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);

    return ret;
}

char* calcular_hash(char dados[256])
{
   unsigned char *digest = kmalloc (sizeof (char) * 256,GFP_KERNEL);
   struct crypto_shash *alg;
   char *hash_alg_name = "sha1";
   int ret, i, j;
   char *hexa_result = kmalloc (sizeof (char) * 256,GFP_KERNEL);
   unsigned int datalen = strlen(dados);

   alg = crypto_alloc_shash(hash_alg_name, CRYPTO_ALG_TYPE_SHASH, 0);

    if (IS_ERR(alg)) {
        pr_info("can't alloc alg %s\n", hash_alg_name);
        printk("PTR_ERR = %lu",PTR_ERR(alg));
        return "erro";
    }

    ret = calc_hash(alg, dados, datalen, digest);
    crypto_free_shash(alg);

   for (i = 0, j=0; i < strlen(digest); i++, j+=2) {
        printk("%2x ", digest[i]);
        sprintf((char*)hexa_result+j,"%02x",digest[i]);
    }

    hexa_result[j] = '\0';

    kfree(digest);

   printk("Cryptodev: Chave recebida para o hash: %s",key);

   return hexa_result;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(cryptodev_init);
module_exit(cryptodev_exit);
