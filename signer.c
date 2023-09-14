#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/cms.h>
#include <openssl/engine.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIG_SECTION_NAME ".text_sig"
#define TEXT_SECTION_NAME ".text"
#define DYN_SECTION ".dynamic"
#define DYNSTR_SECTION ".dynstr"
#define SIG_TMP_FILE_NAME ".signature_tmp"
#define HASH_ALGO "SHA256"

/* Print error message. */
#define ERROR(cond, fmt, ...)                                                  \
  if ((bool)(cond))                                                            \
    err(1, fmt, ##__VA_ARGS__)

/* Print error message with given errno. */
#define ERROR_ENO(cond, eno, fmt, ...)      \
  if ((bool)(cond)){                        \
    errno = eno;                            \
    err(1, fmt, ##__VA_ARGS__);             \
  }                                         \

/* Read PEM encoded private key from file path. */
static EVP_PKEY *read_private_key(const char *private_key_name) {
  EVP_PKEY *private_key;
  BIO *key_file;

  key_file = BIO_new_file(private_key_name, "rb");
  ERROR(!key_file, "Failed to load private key file [%s].", private_key_name);
  private_key = PEM_read_bio_PrivateKey(key_file, NULL, NULL, NULL);
  ERROR(!private_key, "Failed to read private key [%s].", private_key_name);
  BIO_free(key_file);

  return private_key;
}

/* Read PEM encoded X.509 certificate from file path. */
static X509 *read_x509(const char *x509_name) {
  unsigned char buf[2];
  X509 *x509;
  BIO *x509_file;
  int n;

  x509_file = BIO_new_file(x509_name, "rb");
  ERROR(!x509_file, "Failed to load certificate file [%s].", x509_name);
  x509 = PEM_read_bio_X509(x509_file, NULL, NULL, NULL);
  ERROR(!x509, "Failed to read certificate [%s].", x509_name);
  BIO_free(x509_file);

  return x509;
}

/**
 * @brief Calculate the signature of data_buf by using SHA256 + RSA, then saved
 * to tmp file.
 *
 * @param data_buf Data to be signed
 * @param data_len Total bytes of data
 * @param private_key_name Private key file path
 * @param x509_name X509 certificate file path
 * @return unsigned long: Bytes of the signature
 */
static unsigned long calculate_signature(void *data_buf, size_t data_len,
                                         char *private_key_name,
                                         char *x509_name) {
  const EVP_MD *digest_algo;
  EVP_PKEY *private_key;
  CMS_ContentInfo *cms = NULL;
  X509 *x509;
  BIO *sig, *data;
  int opt, n;

  /* Load algorithms from openssl lib. */
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();

  /* Initialize the BIO data buffer. */
  data = BIO_new_mem_buf(data_buf, data_len);

  /* Get private key and X.509 certificate. */
  private_key = read_private_key(private_key_name);
  x509 = read_x509(x509_name);

  /* Get digest algorithm by name. */
  digest_algo = EVP_get_digestbyname(HASH_ALGO);
  ERROR(!digest_algo, "EVP_get_digestbyname");

  /* Initialize the CMS signer */
  cms = CMS_sign(NULL, NULL, NULL, NULL,
                 CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
                     CMS_STREAM);
  ERROR(!cms, "CMS_sign");

  /* Set the CMS signer attributes. */
  ERROR(
      !CMS_add1_signer(cms, x509, private_key, digest_algo,
                       CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP | CMS_NOATTR),
      "CMS_add1_signer");

  /* Get CMS format signature. */
  ERROR(CMS_final(cms, data, NULL, CMS_NOCERTS | CMS_BINARY) < 0, "CMS_final");

  /* Save the signature to tmp file. */
  sig = BIO_new_file(SIG_TMP_FILE_NAME, "wb");
  ERROR(!sig, "File create failed.");
  ERROR(i2d_CMS_bio_stream(sig, cms, NULL, 0) < 0, "%s", "Fail to sign.");

  /* Get signature size (bytes). */
  unsigned long sig_len = BIO_number_written(sig);
  /* Free resources.*/
  ERROR(BIO_free(sig) < 0, "Fail to free signature buffer.");
  ERROR(BIO_free(data) < 0, "Fail to free signature buffer.");
  return sig_len;
}

/* Basic IO helpers. */
static inline size_t read_file(FILE *file, void *buf, size_t size,
                               unsigned long long offset) {
  fseek(file, offset, SEEK_SET);
  return fread(buf, sizeof(char), size, file);
}

/* Copy <size> length bytes from src_file to dst_file. */
void copy_bytes(FILE *src_file, FILE *dst_file, long long size) {
  char c;
  /* When size == -1, copy the all the rest bytes in src_file to dst_file*/
  if (size == -1) {
    while ((c = fgetc(src_file)) != EOF) {
        fputc(c, dst_file);
    }
  } else {
    while (size-- && !feof(src_file)) {
        c = fgetc(src_file);
        fputc(c, dst_file);
    }
  }
}


/* ELF IO helpers. */
static inline int check_elf_header(Elf64_Ehdr *elf_hdr) {
  if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
    ERROR_ENO(1, EBADMSG, "File is not an ELF file.");
    return 0;
  }
  if (elf_hdr->e_ident[EI_CLASS] != ELFCLASS64) {
    ERROR_ENO(1, EBADMSG, "Only support 64-bit ELF file.");
    return 0;
  }
  if (elf_hdr->e_ident[EI_VERSION] != EV_CURRENT){
    ERROR_ENO(1, EBADMSG, "ELF version not support.");
    return 0;
  }

  if (!elf_hdr->e_shoff) {
    ERROR_ENO(1, EBADMSG, "Section header table not found.");
    return 0;
  }

  if (elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
    ERROR_ENO(1, EBADMSG, "Section header struct in wrong size.");
    return 0;
  }

  return 1;
}

/* Get ELF header from file. */
static inline Elf64_Ehdr *read_elf_header(FILE *file) {
  Elf64_Ehdr *elf_header;
  int is_valid;

  elf_header = malloc(sizeof(Elf64_Ehdr));
  ERROR(!elf_header,"Failed to malloc for elf_ex.");

  read_file(file, elf_header, sizeof(Elf64_Ehdr), 0);

  is_valid = check_elf_header(elf_header);
  ERROR_ENO(!is_valid, EBADMSG, "ELF format is not valid.");

  return elf_header;
}

/* Read the section header by given the offset. */
Elf64_Shdr *read_shdr_at_offset(FILE *fp, unsigned long long offset) {
  Elf64_Shdr *shdr;
  shdr = malloc(sizeof(Elf64_Shdr));
  ERROR(!shdr, "Failed to allocate memory for shdr.");

  size_t read_size = read_file(fp, shdr, sizeof(Elf64_Shdr), offset);
  ERROR(read_size != sizeof(Elf64_Shdr) || ferror(fp),"Read ELF file failed.");

  return shdr;
}

Elf64_Shdr *read_shdr_at_index(FILE *fp, Elf64_Ehdr *elf_hdr, Elf64_Half shdr_index) {
  return read_shdr_at_offset(fp, elf_hdr->e_shoff + shdr_index * sizeof(Elf64_Shdr));
}

/* Calculate the signature of .text section and write to tmp file. */
int sign_file(FILE *elf_file, Elf64_Ehdr *elf_hdr, Elf64_Shdr *shstrtab_shdr,
              char *tmp_filename, char *filename, char *private_key_name,
              char *x509_name) {
  FILE *tmp_file, *signature_file;
  char sig_name[] = SIG_SECTION_NAME;
  int sig_name_len = sizeof(sig_name);
  Elf64_Shdr *last_shdr;
  unsigned long sig_len;

  tmp_file = fopen(tmp_filename, "wb+");
  ERROR(!tmp_file, "Failed to create tmp file %s", tmp_filename);

  char *shstrtab = (char *)malloc(shstrtab_shdr->sh_size);
  ERROR(!shstrtab, "Failed to malloc for string table.");
  read_file(elf_file, shstrtab, shstrtab_shdr->sh_size,
            shstrtab_shdr->sh_offset);

  /* shdr_ptr: section header pointer. */
  Elf64_Shdr *shdr_ptr = malloc(sizeof(Elf64_Shdr));
  ERROR(!shdr_ptr,"Failed to malloc for shdr_ptr.");
  for (int i = 0; i < elf_hdr->e_shnum; i++) {
    read_file(elf_file, shdr_ptr, sizeof(Elf64_Shdr),
              elf_hdr->e_shoff + sizeof(Elf64_Shdr) * i);
    char *section_name = shstrtab + shdr_ptr->sh_name;
    /* Find the .text section and calculate signature. */
    if (!memcmp(section_name, TEXT_SECTION_NAME, sizeof(TEXT_SECTION_NAME))) {
      char *section_data = (char *)malloc(shdr_ptr->sh_size);
      ERROR(!section_data, "Failed to malloc for data of section %s.",
            section_name);
      read_file(elf_file, section_data, shdr_ptr->sh_size, shdr_ptr->sh_offset);
      sig_len = calculate_signature(section_data, shdr_ptr->sh_size,
                                    private_key_name, x509_name);
      free(section_data);
      break;
    }
  }

  last_shdr = read_shdr_at_index(elf_file, elf_hdr, elf_hdr->e_shnum - 1);
  ERROR(!last_shdr, "Failed to malloc for last_shdr.");
  signature_file = fopen(SIG_TMP_FILE_NAME, "rb");
  ERROR(!signature_file, "Cannot open tmp signature file");

  char *signature = malloc(sig_len);
  read_file(signature_file, signature, sig_len, 0);

  /* Copy bytes from 0 to .shstrtab section end. */
  fseek(tmp_file, 0, SEEK_SET);
  fseek(elf_file, 0, SEEK_SET);
  copy_bytes(elf_file, tmp_file,
             shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size);
  /* Append signature section name to .shstrtab section. */
  fwrite(sig_name, sizeof(char), sig_name_len, tmp_file);
  /* Copy bytes from .shstrtab section end to last section end (usually size = 0). */
  copy_bytes(elf_file, tmp_file,
             ((last_shdr->sh_offset + last_shdr->sh_size) -
              (shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size)));
  /* Add signature section data */
  fwrite(signature, sizeof(char), sig_len, tmp_file);
  /* Copy bytes from last section end to section header table begin. */
  copy_bytes(elf_file, tmp_file,
             elf_hdr->e_shoff - (last_shdr->sh_offset + last_shdr->sh_size));
  /* Copy section headers table begin to .shstrtab section header*/
  copy_bytes(elf_file, tmp_file, sizeof(Elf64_Shdr) * elf_hdr->e_shstrndx);
  /* Change .shstrtab section size and write .shstrtab section header. */
  shstrtab_shdr->sh_size += sig_name_len;
  fwrite(shstrtab_shdr, sizeof(char), sizeof(Elf64_Shdr), tmp_file);
  /* Move elf_file file ptr to sync with tmp_file. */
  fseek(elf_file, sizeof(Elf64_Shdr), SEEK_CUR);

  /* Update sections which offset after .shstrtab section. */
  int i = elf_hdr->e_shstrndx;
  memcpy(last_shdr, shstrtab_shdr, sizeof(Elf64_Shdr)); 
  while (i + 1 < elf_hdr->e_shnum) {
    fread(last_shdr, sizeof(char), sizeof(Elf64_Shdr), elf_file);
    last_shdr->sh_offset += sig_name_len;
    fwrite(last_shdr, sizeof(char), sizeof(Elf64_Shdr), tmp_file);
    ++i;
  }
  /* Fill in the section header entry for signature section. */
  Elf64_Shdr *new_shdr = malloc(sizeof(Elf64_Shdr));
  memcpy(new_shdr, shstrtab_shdr, sizeof(Elf64_Shdr));
  new_shdr->sh_offset = last_shdr->sh_offset + last_shdr->sh_size;
  new_shdr->sh_name = last_shdr->sh_size - sig_name_len;
  new_shdr->sh_size = sig_len;
  new_shdr->sh_addr = 0;
  new_shdr->sh_addralign = 1;
  new_shdr->sh_flags = SHF_OS_NONCONFORMING;
  new_shdr->sh_type = SHT_PROGBITS;
  new_shdr->sh_info = 0;
  new_shdr->sh_link = 0;
  fwrite(new_shdr, sizeof(char), sizeof(Elf64_Shdr), tmp_file);
  /* Section headers table end */

  /* Copy bytes after section header table, normaly do nothing. */
  copy_bytes(elf_file, tmp_file, -1);

  /* Overwrite ELF header. */
  elf_hdr->e_shnum += 1;
  elf_hdr->e_shoff += (sig_name_len + sig_len);
  fseek(tmp_file, 0, SEEK_SET);
  fwrite(elf_hdr, sizeof(char), sizeof(Elf64_Ehdr), tmp_file);

  free(shstrtab);
  free(shdr_ptr);
  free(signature);
  free(new_shdr);
  fclose(tmp_file);
  fclose(signature_file);
  return sig_len;
}

/* Do some prepare work for signing. */
int prepare_sign(char *private_key_name, char *x509_name, char *elf_name) {
  int ret = EXIT_SUCCESS;
  FILE *elf_file;
  elf_file = fopen(elf_name, "rb");
  ERROR(!elf_file, "Failed to open file [%s]", elf_name);

  /* Get ELF header */
  Elf64_Ehdr *elf_hdr = read_elf_header(elf_file);
  ERROR(!elf_hdr, "Failed to find ELF header [%s]", elf_name);
  /* Get .shstrtab section header */
  Elf64_Shdr *shstrtab_shdr = read_shdr_at_index(elf_file, elf_hdr, elf_hdr->e_shstrndx);
  ERROR(!shstrtab_shdr, "Failed to find .shstrtab section [%s]", elf_name);

  char *tmp_filename = malloc(strlen(elf_name) + 10);
  ERROR(!tmp_filename, "Failed to malloc for tmp_filename");

  strcpy(tmp_filename, elf_name);
  strcat(tmp_filename, ".signed");

  /* Sign one file */
  int sig_len = sign_file(elf_file, elf_hdr, shstrtab_shdr, tmp_filename, elf_name,
            private_key_name, x509_name);
  /* Check sig size*/
  ret = sig_len == 0 ? -1 : 0;
  /* Copy file stat and remove tmp signature file*/
  struct stat elf_stat;
  ret = stat(elf_name, &elf_stat);
  ret = chmod(tmp_filename, elf_stat.st_mode);
  ret = remove(SIG_TMP_FILE_NAME);

  free(tmp_filename);
  free(shstrtab_shdr);
  free(elf_hdr);
  fclose(elf_file);
  return ret;
}

/* Printing the usage */
static __attribute__((noreturn)) void format(void) {
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, "  elf_sign <private_key_path> <x509_path> <elf_file> \n");
  fprintf(stdout, "  -h,         display the help and exit\n");
  fprintf(stdout, "Description:\n");
  fprintf(stdout, "  Sign the <elf-file> with PEM private key <private_key_path> \n");
  fprintf(stdout, "  and public key certificate <x509>.\n");
  fprintf(stdout, "  The signed file will be named <elf_file>.signed, \n");
  fprintf(stdout, "  and the original <elf-file> will be remained.\n");
  exit(2);
}

int main(int argc, char **argv) {
  int opt;

  do {
    opt = getopt(argc, argv, "h");
    switch (opt) {
    case 'h':
      format();
      break;
    case -1:
      break;
    default:
      format();
    }
  } while (opt != -1);

  argc -= optind;
  argv += optind;
  if (argc != 3) {
    format();
  }
  
  /* Get args from argv. */
  char *private_key_name = argv[0];
  char *x509_name = argv[1];
  char *elf_name = argv[2];

  int ret = prepare_sign(private_key_name, x509_name, elf_name);
  if(!ret){
    printf("%s signed successfully.\n", elf_name);
  }
}
