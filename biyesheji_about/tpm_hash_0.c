#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
void HashThis(TSS_HCONTEXT hContext,BYTE *pubKey,UINT32 pubKeysize,BYTE hash[20])
{
	TSS_RESULT result;
	BYTE *digest;
	UINT32 digestLen;
	TSS_HHASH hHashOfESSKey;
	BYTE initialHash[20];
	memset(initialHash,0,20);
	
	result = Tspi_Context_CreateObject(hContext,
		TSS_OBJECT_TYPE_HASH,
		TSS_HASH_SHA1,
		&hHashOfESSKey);
	//DBG("Create Hash object",result);
	result = Tspi_Hash_UpdateHashValue(hHashOfESSKey,
					pubKeysize,
					pubKey);
	//DBG("Hash in the public key",result);
	result = Tspi_Hash_GetHashValue(hHashOfESSKey,
					&digestLen,
					&digest);
	//DBG("Get the hashed result",result);
	memcpy(hash,digest,20);
}
int main_v1_1( void )
{
	char		*function = "Tspi_Data_Seal01";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HKEY	hKey;
	TSS_HPOLICY	hSrkPolicy;
	BYTE		*rgbDataToSeal = "This is a test.  1 2 3.";
	BYTE		rgbPcrValue[20];
	TSS_HENCDATA	hEncData;
	TSS_HPCRS	hPcrComposite;
	UINT32		BlobLength;
	UINT32		ulDataLength = strlen(rgbDataToSeal);
	TSS_UUID	uuid;
	TSS_RESULT	result;
	TSS_FLAG	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
				TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
				TSS_KEY_NOT_MIGRATABLE;





		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create hKey
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_SEAL, &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hEncData)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hSrkPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hSrkPolicy, TESTSUITE_SRK_SECRET_MODE,
					TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif

	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_PCRS,
					0, &hPcrComposite );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hPcrComposite)",
				result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_PcrComposite_SetPcrValue( hPcrComposite, 8, 20, rgbPcrValue );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_PcrComposite_SetPcrValue", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_PcrComposite_SetPcrValue( hPcrComposite, 9, 20, rgbPcrValue );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_PcrComposite_SetPcrValue", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Data Seal
	result = Tspi_Data_Seal( hEncData, hSRK, ulDataLength, rgbDataToSeal, hPcrComposite );
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit(result);
}


int main()
{

}
