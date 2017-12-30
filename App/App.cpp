/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "../Enclave3/Enclave3_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "omp.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;


sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;
sgx_enclave_id_t e3_enclave_id = 0;
/*
#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"
#define ENCLAVE3_PATH "libenclave3.so"
*/

//======================================================================
// this Error handling code is taken and modified from:
// https://github.com/01org/linux-sgx/tree/master/SampleCode/Cxx11SGXDemo
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "SGX_ERROR_UNEXPECTED: Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "SGX_ERROR_INVALID_PARAMETER: Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "SGX_ERROR_OUT_OF_MEMORY: Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "SGX_ERROR_ENCLAVE_LOST: Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "SGX_ERROR_INVALID_ENCLAVE: Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "SGX_ERROR_INVALID_SIGNATURE: Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "SGX_ERROR_OUT_OF_EPC: Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "SGX_ERROR_NO_DEVICE: Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "SGX_ERROR_MEMORY_MAP_CONFLICT: Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "SGX_ERROR_INVALID_METADATA: Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX_ERROR_DEVICE_BUSY: SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "SGX_ERROR_INVALID_VERSION: Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "SGX_ERROR_INVALID_ATTRIBUTE: Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "SGX_ERROR_ENCLAVE_FILE_ACCESS: Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "SGX_ERROR_NDEBUG_ENCLAVE: The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

//Check error conditions for loading enclave 
//modified to give more detailed information
void print_error_message(sgx_status_t ret)
{
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
	size_t idx = 0;
    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
			printf("\nError (%d): %s\n", ret, sgx_errlist[idx].msg);
            if(NULL != sgx_errlist[idx].sug)
            {
				printf("Info: %s\n", sgx_errlist[idx].sug);
			}
            break;
        }
    }
    
    if (idx == ttl){
		printf("Error: Unexpected error occurred.\n");
	}
}
//Error handling code ends
//======================================================================

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

sgx_status_t initialize_enclave(char *ENCLAVE_PATH, sgx_launch_token_t *launch_token, int *launch_token_updated, sgx_enclave_id_t *enclave_id)
{
    sgx_status_t ret;
    
    ret = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, launch_token, launch_token_updated, enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}

sgx_status_t enclavesLocalAttestation(sgx_enclave_id_t source_enclave_id, sgx_enclave_id_t dest_enclave_id, uint32_t *ret_status, int *error_stage){
	
	sgx_status_t status;	
	
	//Test Create session between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_create_session(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	if(status!=SGX_SUCCESS ||*ret_status !=0 ){
		*error_stage=-1;
		return status;
	}
	//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_enclave_to_enclave_call(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	if(status!=SGX_SUCCESS){
		*error_stage=-2;
		return status;
	}
	
	//Test message exchange between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_message_exchange(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	if(status!=SGX_SUCCESS){
		*error_stage=-3;
		return status;
	}
	
	return status;
}

void reportLocalAttestationSuccess(sgx_enclave_id_t source_enclave_id, sgx_enclave_id_t dest_enclave_id){
	printf("\nLocal attestation between Source Enclave (%d) and Destination Enclave (%d) Successfull",source_enclave_id,dest_enclave_id);
	printf("\nSecure Channel Establishment between Source Enclave (%d) and Destination Enclave (%d) was successful",source_enclave_id,dest_enclave_id);
	printf("\nEnclave to Enclave Call between Source Enclaves (%d) and Destination Enclaves (%d) was successful",source_enclave_id,dest_enclave_id);
	printf("\nMessage Exchange between Source Enclaves (%d) and Destination Enclaves (%d) was successful",source_enclave_id,dest_enclave_id);
}

void reportLocalAttestationError(sgx_enclave_id_t source_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_status_t status, uint32_t ret_status, int error_stage){
	printf("\nLocal attestation between source enclave (%d) and destination enclave (%d) Failed",source_enclave_id,dest_enclave_id);
	if(error_stage==-1){
		if(status!=SGX_SUCCESS){
			printf("\nEnclave1_test_create_session Ecall failed: Error code is %x", status);
		}		
		if(ret_status!=0)
		{
			printf("\nSession establishment and key exchange failure between Source Enclave (%d) and Destination Enclave (%d): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
		}
	}
	else if(error_stage==-2){
		if(status!=SGX_SUCCESS){
			printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
		}
		
		if(ret_status!=0)
		{
			printf("\n\nEnclave to Enclave Call failure between Source Enclaves (%d) and Destination (%d): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
		}
	}
	else if(error_stage==-3){
		if(status!=SGX_SUCCESS){
			printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
		}
		
		if(ret_status!=0)
		{
			printf("\nMessage Exchange failure between Source Enclaves (%d) and Destination (%d): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
		}
	}	
}

/*
uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE3_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e3_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e3_enclave_id, enclave_temp_no));



    return SGX_SUCCESS;
}
*/
int _tmain(int argc, _TCHAR* argv[])
{
    UNUSED(argc);
    UNUSED(argv);
    
    //enclave 1
    sgx_launch_token_t launch_token1 = {0};
    int launch_token_updated1 = 0;
    char *E_PATH1="libenclave1.so";
    sgx_status_t ret1;
    
    //enclave 2
    sgx_launch_token_t launch_token2 = {0};
    int launch_token_updated2 = 0;
    char *E_PATH2="libenclave2.so";
    sgx_status_t ret2;
    
    //enclave 3
    sgx_launch_token_t launch_token3 = {0};
    int launch_token_updated3 = 0;
    char *E_PATH3="libenclave3.so";
    sgx_status_t ret3;
    
    //keep record of enclaves in map
    uint32_t enclave_temp_no;
    enclave_temp_no=0;
    
    ret1 = initialize_enclave(E_PATH1, &launch_token1, &launch_token_updated1, &e1_enclave_id);
    if(ret1==SGX_SUCCESS){
		enclave_temp_no++;
		g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));
	}
	else{
        print_error_message(ret1);
        //return -1; 
    }
    
    ret2 = initialize_enclave(E_PATH2, &launch_token2, &launch_token_updated2, &e2_enclave_id);
    if(ret1==SGX_SUCCESS){
		enclave_temp_no++;
		g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));
	}
	else{
        print_error_message(ret2);
        //return -1; 
    }
    ret3 = initialize_enclave(E_PATH3, &launch_token3, &launch_token_updated3, &e3_enclave_id);
    if(ret1==SGX_SUCCESS){
		enclave_temp_no++;
		g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e3_enclave_id, enclave_temp_no));
	}
	else{
        print_error_message(ret3);
        //return -1; 
    }

	//if all the enclaves were not loaded, exit ! 
	//make sure that before exiting, unload the enclaves which were loaded successfully
	if(ret1!=SGX_SUCCESS ||ret2!=SGX_SUCCESS ||ret3!=SGX_SUCCESS){
		printf("\nExiting as all enclaves could not be initialized properly");
		if(ret1==SGX_SUCCESS){
			sgx_destroy_enclave(e1_enclave_id);
		}
		if(ret2==SGX_SUCCESS){
			sgx_destroy_enclave(e2_enclave_id);
		}
		if(ret3==SGX_SUCCESS){
			sgx_destroy_enclave(e3_enclave_id);
		}
		return 0;
	}
	
    printf("\nAvaliable Enclaves");
    printf("\nEnclave1 - EnclaveID %" PRIx64, e1_enclave_id);
    printf("\nEnclave2 - EnclaveID %" PRIx64, e2_enclave_id);
    printf("\nEnclave3 - EnclaveID %" PRIx64, e3_enclave_id);
    
	//attestation goes here
	
	sgx_status_t status;
	uint32_t ret_status;
	int error_stage;
    
    sgx_status_t status12;
	uint32_t ret_status12;
	int error_stage12;
    
    sgx_status_t status13;
    uint32_t ret_status13;
    int error_stage13;
    
    sgx_status_t status23;
    uint32_t ret_status23;
    int error_stage23;
    
    sgx_status_t status31;
    uint32_t ret_status31;
    int error_stage31;
    
    //local attestation 1 &2
    status12 = enclavesLocalAttestation(e1_enclave_id, e2_enclave_id, &ret_status12, &error_stage12);
    if(status12==SGX_SUCCESS && ret_status12==0){
		reportLocalAttestationSuccess(e1_enclave_id, e2_enclave_id);
	}
	else{
		reportLocalAttestationError(e1_enclave_id, e2_enclave_id, status12,ret_status12, error_stage12);
	}
    
    //local attestation 1 & 3
    status13 = enclavesLocalAttestation(e1_enclave_id, e3_enclave_id, &ret_status13, &error_stage13);
    if(status13==SGX_SUCCESS && ret_status13==0){
		reportLocalAttestationSuccess(e1_enclave_id, e3_enclave_id);
	}
	else{
		reportLocalAttestationError(e1_enclave_id, e3_enclave_id, status13,ret_status13, error_stage13);
	}
	
	//local attestation 2 & 3
	status23 = enclavesLocalAttestation(e2_enclave_id, e3_enclave_id, &ret_status23, &error_stage23);
    if(status23==SGX_SUCCESS && ret_status23==0){
		reportLocalAttestationSuccess(e2_enclave_id, e3_enclave_id);
	}
	else{
		reportLocalAttestationError(e2_enclave_id, e3_enclave_id, status23,ret_status23, error_stage23);
	}
	
	//local attestation 3 & 1
	status31 = enclavesLocalAttestation(e3_enclave_id, e1_enclave_id, &ret_status31, &error_stage31);
    if(status31==SGX_SUCCESS && ret_status31==0){
		reportLocalAttestationSuccess(e3_enclave_id, e1_enclave_id);
	}
	else{
		reportLocalAttestationError(e3_enclave_id, e1_enclave_id, status31,ret_status31, error_stage31);
	}
    /*
    //Test Create session between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\nSession establishment and key exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
		}
	}

	//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_enclave_to_enclave_call(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nEnclave to Enclave Call between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Call failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
		}
	}
	//Test message exchange between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nMessage Exchange between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nMessage Exchange failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
		}
	}
	
	
	
	//Test Create session between Enclave1(Source) and Enclave3(Destination)
	status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nSession establishment and key exchange failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test Enclave to Enclave call between Enclave1(Source) and Enclave3(Destination)
	status = Enclave1_test_enclave_to_enclave_call(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nEnclave to Enclave Call between Source (E1) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Call failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test message exchange between Enclave1(Source) and Enclave3(Destination)
	status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nMessage Exchange between Source (E1) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nMessage Exchange failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
		}
	}

	//Test Create session between Enclave2(Source) and Enclave3(Destination)
	status = Enclave2_test_create_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave2_test_create_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nSecure Channel Establishment between Source (E2) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nSession establishment and key exchange failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test Enclave to Enclave call between Enclave2(Source) and Enclave3(Destination)
	status = Enclave2_test_enclave_to_enclave_call(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave2_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nEnclave to Enclave Call between Source (E2) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Call failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test message exchange between Enclave2(Source) and Enclave3(Destination)
	status = Enclave2_test_message_exchange(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave2_test_message_exchange Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nMessage Exchange between Source (E2) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nMessage Exchange failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
		}
	}

	//Test Create session between Enclave3(Source) and Enclave1(Destination)
	status = Enclave3_test_create_session(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave3_test_create_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nSecure Channel Establishment between Source (E3) and Destination (E1) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nSession establishment and key exchange failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
		}
	}
	//Test Enclave to Enclave call between Enclave3(Source) and Enclave1(Destination)
	status = Enclave3_test_enclave_to_enclave_call(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave3_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nEnclave to Enclave Call between Source (E3) and Destination (E1) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nEnclave to Enclave Call failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
		}
	}
	//Test message exchange between Enclave3(Source) and Enclave1(Destination)
	status = Enclave3_test_message_exchange(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave3_test_message_exchange Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nMessage Exchange between Source (E3) and Destination (E1) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nMessage Exchange failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
		}
	}
*/

	//Test Closing Session between Enclave1(Source) and Enclave2(Destination)
	status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nClose Session between Source (E1) and Destination (E2) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nClose session failure between Source (E1) and Destination (E2): Error code is %x", ret_status);
		}
	}
	//Test Closing Session between Enclave1(Source) and Enclave3(Destination)
	status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nClose Session between Source (E1) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nClose session failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test Closing Session between Enclave2(Source) and Enclave3(Destination)
	status = Enclave2_test_close_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave2_test_close_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nClose Session between Source (E2) and Destination (E3) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nClose session failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
		}
	}
	//Test Closing Session between Enclave3(Source) and Enclave1(Destination)
	status = Enclave3_test_close_session(e3_enclave_id, &ret_status, e3_enclave_id, e1_enclave_id);
	if (status!=SGX_SUCCESS)
	{
		printf("Enclave3_test_close_session Ecall failed: Error code is %x", status);
	}
	else
	{
		if(ret_status==0)
		{
			printf("\n\nClose Session between Source (E3) and Destination (E1) Enclaves successful !!!");
		}
		else
		{
			printf("\n\nClose session failure between Source (E3) and Destination (E1): Error code is %x", ret_status);
		}
	}

	
	//attestation ends
	

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);
    sgx_destroy_enclave(e3_enclave_id);

    //waitForKeyPress();

    return 0;
}
