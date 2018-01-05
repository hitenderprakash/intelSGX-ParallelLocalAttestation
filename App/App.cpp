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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "omp.h"


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

//flag ENCLAVE_TO_ENCLAVE_COMM_TYPE
#define CREATE_SESSION 1
#define ENC_TO_ENC_CALL 2
#define ENC_TO_ENC_MSG_EXCHANGE 3
#define CLOSE_SESSION 4

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
    {
        SGX_ERROR_SERVICE_UNAVAILABLE,
        "SGX_ERROR_SERVICE_UNAVAILABLE: The Plateform services are not running.",
        "Please try to restart the platform service: sudo service aesmd restart"
    }
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

//  Method to perform 
//  1  Create session between two enclaves
//  2  Enclave to enclave call
//  3  Msg exchange between two enclaves
//  4  closing session between two enclaves
// particular action depends on the flag ENCLAVE_TO_ENCLAVE_COMM_TYPE
sgx_status_t EnclaveToEnclaveComm(sgx_enclave_id_t source_enclave_id, sgx_enclave_id_t dest_enclave_id, uint32_t *ret_status, uint32_t ENCLAVE_TO_ENCLAVE_COMM_TYPE){
	sgx_status_t status;
	if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==CREATE_SESSION){
		//Test Create session between Enclave1(Source) and Enclave2(Destination)
		status = Enclave1_test_create_session(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==ENC_TO_ENC_CALL){
		//Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
		status = Enclave1_test_enclave_to_enclave_call(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE== ENC_TO_ENC_MSG_EXCHANGE){
		//Test message exchange between Enclave1(Source) and Enclave2(Destination)
		status = Enclave1_test_message_exchange(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==CLOSE_SESSION){
		//Test close session between Enclave1(Source) and Enclave2(Destination)
		status = Enclave1_test_close_session(source_enclave_id, ret_status, source_enclave_id, dest_enclave_id);
	}	
	return status;
}

//  Method to report success or error on 
//  1  Create session between two enclaves
//  2  Enclave to enclave call
//  3  Msg exchange between two enclaves
//  4  closing session between two enclaves
// particular action depends on the flag ENCLAVE_TO_ENCLAVE_COMM_TYPE
void reportEnclaveToEnclaveCommStatus(sgx_enclave_id_t source_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_status_t status, uint32_t ret_status, uint32_t ENCLAVE_TO_ENCLAVE_COMM_TYPE){	
	if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==CREATE_SESSION){
		if (status!=SGX_SUCCESS || ret_status==0){
			printf("\nSecure Channel Establishment between Source Enclave (%lu) and Destination Enclave (%lu) was successful",source_enclave_id,dest_enclave_id);
		}
		else{
			if(status!=SGX_SUCCESS){
				printf("\nEnclave1_test_create_session Ecall failed: Error code is %x", status);
			}		
			if(ret_status!=0)
			{
				printf("\nSession establishment and key exchange failure between Source Enclave (%lu) and Destination Enclave (%lu): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
			}
		}
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==ENC_TO_ENC_CALL){
		if (status!=SGX_SUCCESS || ret_status==0){
			printf("\nEnclave to Enclave Call between Source Enclaves (%lu) and Destination Enclaves (%lu) was successful",source_enclave_id,dest_enclave_id);
		}
		else{
			if(status!=SGX_SUCCESS){
				printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
			}
			
			if(ret_status!=0)
			{
				printf("\n\nEnclave to Enclave Call failure between Source Enclaves (%lu) and Destination Enclave(%lu): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
			}

		}
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE== ENC_TO_ENC_MSG_EXCHANGE){
		if (status!=SGX_SUCCESS || ret_status==0){
			printf("\nMessage Exchange between Source Enclaves (%lu) and Destination Enclaves (%lu) was successful",source_enclave_id,dest_enclave_id);
		}
		else{
			if(status!=SGX_SUCCESS){
				printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
			}
			
			if(ret_status!=0)
			{
				printf("\nMessage Exchange failure between Source Enclaves (%lu) and Destination Enclave(%lu): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
			}
		}
	}
	else if(ENCLAVE_TO_ENCLAVE_COMM_TYPE==CLOSE_SESSION){
		if (status!=SGX_SUCCESS || ret_status==0){
			printf("\nClose Session between Source Enclave (%lu) and Destination Enclave (%lu) successful",source_enclave_id,dest_enclave_id);
		}
		else{
			if(status!=SGX_SUCCESS)
			{
				printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
			}
			if(ret_status!=0)
			{
				printf("\nClose session failure between Source Enclave (%lu) and Destination Enclave (%lu): Error code is %x",source_enclave_id,dest_enclave_id,ret_status);
			}
		}
	}	
}

int _tmain(int argc, _TCHAR* argv[])
{
    UNUSED(argc);
    UNUSED(argv);
    
    //enclave 1
    sgx_launch_token_t launch_token1 = {0};
    int launch_token_updated1 = 0;
    char *E_PATH1=(char*)"libenclave1.so";
    sgx_status_t ret1;
    
    //enclave 2
    sgx_launch_token_t launch_token2 = {0};
    int launch_token_updated2 = 0;
    char *E_PATH2=(char*)"libenclave2.so";
    sgx_status_t ret2;
    
    //enclave 3
    sgx_launch_token_t launch_token3 = {0};
    int launch_token_updated3 = 0;
    char *E_PATH3=(char*)"libenclave3.so";
    sgx_status_t ret3;
    
    //keep record of enclaves in map
    uint32_t enclave_temp_no;
    enclave_temp_no=0;
    
    // parallel enclave creation=================================
    printf("\n\n====Enclaves creation session section==========");
    #pragma omp parallel
	{
		#pragma omp sections
		{
			#pragma omp section
			{
				ret1 = initialize_enclave(E_PATH1, &launch_token1, &launch_token_updated1, &e1_enclave_id);
				printf("\nThread: %d created Enclave %lu",omp_get_thread_num(),e1_enclave_id);
			}
			#pragma omp section
			{
				ret2 = initialize_enclave(E_PATH2, &launch_token2, &launch_token_updated2, &e2_enclave_id);
				printf("\nThread: %d created Enclave %lu",omp_get_thread_num(),e2_enclave_id);
			}
			#pragma omp section
			{
				ret3 = initialize_enclave(E_PATH3, &launch_token3, &launch_token_updated3, &e3_enclave_id);
				printf("\nThread: %d created Enclave %lu",omp_get_thread_num(),e3_enclave_id);
			}
		}
	}
    // parallel enclave creation=================================
    
    //ret1 = initialize_enclave(E_PATH1, &launch_token1, &launch_token_updated1, &e1_enclave_id);
    if(ret1==SGX_SUCCESS){
		enclave_temp_no++;
		g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));
	}
	else{
        print_error_message(ret1);
        //return -1; 
    }
    
    //ret2 = initialize_enclave(E_PATH2, &launch_token2, &launch_token_updated2, &e2_enclave_id);
    if(ret1==SGX_SUCCESS){
		enclave_temp_no++;
		g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));
	}
	else{
        print_error_message(ret2);
        //return -1; 
    }
    //ret3 = initialize_enclave(E_PATH3, &launch_token3, &launch_token_updated3, &e3_enclave_id);
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
		printf("\n");
		return 0;
	}
	

    printf("\n\n====Avaliable Enclaves===================");
    printf("\nEnclave1 - EnclaveID %" PRIx64, e1_enclave_id);
    printf("\nEnclave2 - EnclaveID %" PRIx64, e2_enclave_id);
    printf("\nEnclave3 - EnclaveID %" PRIx64, e3_enclave_id);

    
	//attestation goes here
    sgx_status_t status12;
	uint32_t ret_status12;
    
    sgx_status_t status13;
    uint32_t ret_status13;
    
    sgx_status_t status23;
    uint32_t ret_status23;
    
    sgx_status_t status31;
    uint32_t ret_status31;
    
    printf("\n\n====Enclaves to Enclave create session section==========");   
    //local attestation 1 &2
    status12 = EnclaveToEnclaveComm(e1_enclave_id, e2_enclave_id, &ret_status12, CREATE_SESSION);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e2_enclave_id, status12,ret_status12, CREATE_SESSION);
    //local attestation 1 & 3
    status13 = EnclaveToEnclaveComm(e1_enclave_id, e3_enclave_id, &ret_status13, CREATE_SESSION);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e3_enclave_id, status13,ret_status13, CREATE_SESSION);
    
	//local attestation 2 & 3
	status23 = EnclaveToEnclaveComm(e2_enclave_id, e3_enclave_id, &ret_status23, CREATE_SESSION);
	reportEnclaveToEnclaveCommStatus(e2_enclave_id, e3_enclave_id, status23,ret_status23,CREATE_SESSION);
	
	//local attestation 3 & 1
	status31 = EnclaveToEnclaveComm(e3_enclave_id, e1_enclave_id, &ret_status31, CREATE_SESSION);
	reportEnclaveToEnclaveCommStatus(e3_enclave_id, e1_enclave_id, status31,ret_status31,CREATE_SESSION);
	
	printf("\n\n====Enclaves to Enclave call section==========");
    //enclave to enclave msg call 1 &2
    status12 = EnclaveToEnclaveComm(e1_enclave_id, e2_enclave_id, &ret_status12, ENC_TO_ENC_CALL);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e2_enclave_id, status12,ret_status12, ENC_TO_ENC_CALL);
    //enclave to enclave msg call 1 & 3
    status13 = EnclaveToEnclaveComm(e1_enclave_id, e3_enclave_id, &ret_status13, ENC_TO_ENC_CALL);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e3_enclave_id, status13,ret_status13, ENC_TO_ENC_CALL);
    
	//enclave to enclave msg call 2 & 3
	status23 = EnclaveToEnclaveComm(e2_enclave_id, e3_enclave_id, &ret_status23, ENC_TO_ENC_CALL);
	reportEnclaveToEnclaveCommStatus(e2_enclave_id, e3_enclave_id, status23,ret_status23,ENC_TO_ENC_CALL);
	
	//enclave to enclave msg call 3 & 1
	status31 = EnclaveToEnclaveComm(e3_enclave_id, e1_enclave_id, &ret_status31, ENC_TO_ENC_CALL);
	reportEnclaveToEnclaveCommStatus(e3_enclave_id, e1_enclave_id, status31,ret_status31,ENC_TO_ENC_CALL);
	
	printf("\n\n====Enclaves to Enclave Msg Exchange session section==========");
    //enclave to enclave msg exchange 1 &2
    status12 = EnclaveToEnclaveComm(e1_enclave_id, e2_enclave_id, &ret_status12, ENC_TO_ENC_MSG_EXCHANGE);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e2_enclave_id, status12,ret_status12, ENC_TO_ENC_MSG_EXCHANGE);
    //enclave to enclave msg exchange 1 & 3
    status13 = EnclaveToEnclaveComm(e1_enclave_id, e3_enclave_id, &ret_status13, ENC_TO_ENC_MSG_EXCHANGE);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e3_enclave_id, status13,ret_status13, ENC_TO_ENC_MSG_EXCHANGE);
    
	//enclave to enclave msg exchange 2 & 3
	status23 = EnclaveToEnclaveComm(e2_enclave_id, e3_enclave_id, &ret_status23, ENC_TO_ENC_MSG_EXCHANGE);
	reportEnclaveToEnclaveCommStatus(e2_enclave_id, e3_enclave_id, status23,ret_status23,ENC_TO_ENC_MSG_EXCHANGE);
	
	//enclave to enclave msg exchange 3 & 1
	status31 = EnclaveToEnclaveComm(e3_enclave_id, e1_enclave_id, &ret_status31, ENC_TO_ENC_MSG_EXCHANGE);
	reportEnclaveToEnclaveCommStatus(e3_enclave_id, e1_enclave_id, status31,ret_status31,ENC_TO_ENC_MSG_EXCHANGE);

	printf("\n\n====Close Enclaves to Enclave  session section==========");
	/*#pragma omp parallel
	{
		#pragma omp sections
		{
			#pragma omp section
			{
				status12 = EnclaveToEnclaveComm(e1_enclave_id, e2_enclave_id, &ret_status12, CLOSE_SESSION);
			}
			#pragma omp section
			{
				status13 = EnclaveToEnclaveComm(e1_enclave_id, e3_enclave_id, &ret_status13, CLOSE_SESSION);
			}
			#pragma omp section
			{
				status23 = EnclaveToEnclaveComm(e2_enclave_id, e3_enclave_id, &ret_status23, CLOSE_SESSION);
			}
			#pragma omp section
			{
				status31 = EnclaveToEnclaveComm(e3_enclave_id, e1_enclave_id, &ret_status31, CLOSE_SESSION);
			}
		}
	}*/
	
	//closing session between enclave 1 &2
    status12 = EnclaveToEnclaveComm(e1_enclave_id, e2_enclave_id, &ret_status12, CLOSE_SESSION);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e2_enclave_id, status12,ret_status12, CLOSE_SESSION);
    //closing session between enclave 1 &3
    status13 = EnclaveToEnclaveComm(e1_enclave_id, e3_enclave_id, &ret_status13, CLOSE_SESSION);
    reportEnclaveToEnclaveCommStatus(e1_enclave_id, e3_enclave_id, status13,ret_status13, CLOSE_SESSION);
	//closing session between enclave 2 &3
	status23 = EnclaveToEnclaveComm(e2_enclave_id, e3_enclave_id, &ret_status23, CLOSE_SESSION);
	reportEnclaveToEnclaveCommStatus(e2_enclave_id, e3_enclave_id, status23,ret_status23, CLOSE_SESSION);
	//closing session between enclave 3 &1
	status31 = EnclaveToEnclaveComm(e3_enclave_id, e1_enclave_id, &ret_status31, CLOSE_SESSION);
	reportEnclaveToEnclaveCommStatus(e3_enclave_id, e1_enclave_id, status31,ret_status31,CLOSE_SESSION);
	
	// parallel enclave destruction=================================
	printf("\n\n====Destroying enclaves section==========");
    #pragma omp parallel
	{
		#pragma omp sections
		{
			#pragma omp section
			{
				sgx_destroy_enclave(e1_enclave_id);
				printf("\nThread: %d destryed Enclave %lu",omp_get_thread_num(),e1_enclave_id);
			}
			#pragma omp section
			{
				sgx_destroy_enclave(e2_enclave_id);
				printf("\nThread: %d destryed Enclave %lu",omp_get_thread_num(),e2_enclave_id);
			}
			#pragma omp section
			{
				sgx_destroy_enclave(e3_enclave_id);
				printf("\nThread: %d destryed Enclave %lu",omp_get_thread_num(),e3_enclave_id);
			}
		}
	}

	printf("\n");
    return 0;
}
