#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <tss/platform.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>


TSS_HCONTEXT hContext;
TSS_HTPM hTPM;

int verify_checksum(BYTE *digest, 
		UINT32 digestLen, 
		const char * checksum_file)
{
  int i, match = 0;
  char checksum_string[64];
  BYTE checksum[32];
  FILE *fp = fopen(checksum_file, "r");
  if(fp == NULL) {
    fprintf(stderr, "Cannot open the checksum file %s!\n", checksum_file);
    return 0;
  }

  fscanf(fp, "%63s ", checksum_string);

  if(digestLen*2 != strlen(checksum_string)) {
    fprintf(stderr, "Digest length does not match!\n");
    goto out;
  }

  for(i=0; i< digestLen; i++) {
    char str[3]; 
    sprintf(str, "%02x", digest[i]);
    if(str[0] != checksum_string[i*2] || str[1] != checksum_string[i*2+1])
      goto out;
  }

  match = 1;

out:
  fclose(fp);  
  return match;
}


int main(int argc, char *argv[])
{
  FILE *fp;
  TSS_HHASH hHash;
  char buf[1024];
  int r;
  BYTE *digest = NULL, *PcrValue;
  UINT32 digestLen=0, PcrValueLength;
  TSS_HPCRS hPcrs;


  if(argc < 3){
    printf("USAGE: %s program_to_load checksum_file\n", argv[0]);
    return -1;
  }


  /* open the program file */
  fp = fopen(argv[1], "r");
  if(fp == NULL) {
    fprintf(stderr, "Cannot read %s\n", argv[1]);
    return -1;
  }


  /* initilize objects related to TPM */
  Tspi_Context_Create(&hContext);
  Tspi_Context_Connect(hContext, NULL);
  Tspi_Context_GetTpmObject(hContext, &hTPM);

  /* initialize HASH object in TPM */
  Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, 
		TSS_HASH_SHA1, &hHash);

  //TODO: read the program file and call Tspi_Hash_UpdateHashValue
  // to calculate the hash value

  //TODO; call Tspi_Hash_GetHashValue to obtain the hash value

  /* call verify_checksum to verify the hash value */
  if(!verify_checksum(digest, digestLen, argv[2])) {
    printf("Measurement failed!\n");
    goto out;
  }

  printf("Measurement is successful!\n");

  Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPcrs);
  Tspi_PcrComposite_SelectPcrIndex(hPcrs, 16);

  //TODO: call Tspi_TPM_PcrReset to reset the PCR #16

  //TODO: call Tspi_TPM_PcrExtend to extend PCR #16 with the hash value


  /* now we can launch the program */
  printf("Now launch the program %s...\n", argv[1]);
  system(argv[1]);
  printf("The program %s has terminated.\n", argv[1]);

out:
  Tspi_Context_FreeMemory(hContext, digest);

  fclose(fp);
  return 0;
}

