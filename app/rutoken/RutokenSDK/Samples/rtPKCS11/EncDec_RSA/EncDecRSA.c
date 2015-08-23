/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд шифрования/расшифрования на ключе RSA:            *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - шифрование сообщения на демонстрационном ключе RSA;                 *
*  - расшифрование зашифрованнного сообщения на демонстрационном ключе;  *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Пример использует объекты, созданные в памяти Рутокен примером         *
* CreateRSA.                                                             *
*************************************************************************/

#include "Common.h"

/* Шаблон для поиска открытого ключа RSA */
CK_ATTRIBUTE attrPubKeyFindTempl[] =
{
	{ CKA_ID, &KeyPairIDRSA, sizeof(KeyPairIDRSA) - 1},
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey)}
};

/* Шаблон для поиска закрытого ключа RSA */
CK_ATTRIBUTE attrPrivKeyFindTempl[] =
{
	{ CKA_ID, &KeyPairIDRSA, sizeof(KeyPairIDRSA) - 1},
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey)}
};

/* Данные для шифрования */
CK_BYTE pbtData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

/************************************************************************
* Получить массив хэндлов объектов, соответствующих критериям поиска    *
************************************************************************/
BOOL FindObjects(IN CK_SESSION_HANDLE hSession,               // Хэндл открытой сессии
                 IN CK_FUNCTION_LIST_PTR pFunctionList,       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
                 IN CK_ATTRIBUTE_PTR pTemplate,               // Указатель на шаблон, в который помещены атрибуты для поиска
                 IN CK_ULONG ulCount,                         // Количество атрибутов в шаблоне поиска
                 OUT CK_OBJECT_HANDLE_PTR* pphObject,         // Указатель на массив хэндлов объектов, соответствующих критериям поиска
                 OUT CK_ULONG* pulObjectCount,                // Количество хэндлов в массиве
                 OUT CK_RV* prv                               // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
                 )
{
	CK_RV rvTemp = CKR_OK;         // Вспомогательная переменная для хранения кода возврата
	*pulObjectCount = 0;
	*pphObject = NULL_PTR;

	while (TRUE)
	{
		/**********************************************************************
		* Инициализировать операцию поиска                                    *
		**********************************************************************/
		printf(" C_FindObjectsInit");
		*prv = pFunctionList->C_FindObjectsInit(hSession,
		                                        pTemplate,
		                                        ulCount);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Найти все объекты, соответствующие критериям поиска                 *
		**********************************************************************/
		printf(" C_FindObjects");

		// Считаем, что максимальное количество объектов не превышает 100
		*pphObject = (CK_OBJECT_HANDLE*)malloc(100 * sizeof(CK_OBJECT_HANDLE));
		memset(*pphObject,
		       0,
		       (100 * sizeof(CK_OBJECT_HANDLE)));

		*prv = pFunctionList->C_FindObjects(hSession,
		                                    *pphObject,
		                                    100,
		                                    pulObjectCount);
		if (*prv != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		break;
	}

	/**********************************************************************
	* Деинициализировать операцию поиска                                  *
	**********************************************************************/

	printf(" C_FindObjectsFinal");
	rvTemp = pFunctionList->C_FindObjectsFinal(hSession);
	if (rvTemp != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	if (*prv == CKR_OK)
		printf("Search has been completed.\n"
		       "Objects found: %d \n",
		       (int)*pulObjectCount);
	else
	{
		printf("Search failed!\n");
		if (pphObject)
		{
			free(pphObject);
			*pphObject = NULL_PTR;
			*pulObjectCount = 0;
		}
	}

	return *prv == CKR_OK;
}


/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                                        // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                             // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;                     // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;                 // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                                  // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                                          // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE_PTR ahKeys = NULL_PTR;                            // Указатель на массив хэндлов ключей, соответствующих критериям поиска
	CK_ULONG ulKeysNumber = 0;                                         // Количество хэндлов ключей в массиве

#ifdef HAVEMSCRYPTOAPI
	HCRYPTPROV hProv = NULL_PTR;                                       // Хэндл криптопровайдера
	HCRYPTKEY hKey = NULL_PTR;                                         // Хэндл ключа
	BLOBHEADER blobHeader;                                             // Структура данных типа BLOBHEADER, является частью открытого ключа в формате MS CryptoAPI
	RSAPUBKEY pubKey;                                                  // Структура данных типа RSAPUBKEY, является частью открытого ключа в формате MS CryptoAPI
#endif

	PBYTE pbtCAPIPublicKey = NULL_PTR;                                    // Указатель на буфер с открытым ключом в формате MS CryptoAPI
	DWORD dwCAPIPublicKeySize = 0;                                        // Размер буфера с открытым ключом в формате MS CryptoAPI, в байтах

	CK_ATTRIBUTE attrModulus = {CKA_MODULUS, NULL_PTR, 0};                // Структура данных типа CK_ATTRIBUTE для хранения значения атрибута CKA_MODULUS
	CK_ATTRIBUTE attrPublicExponent = {CKA_PUBLIC_EXPONENT, NULL_PTR, 0}; // Структура данных типа CK_ATTRIBUTE для хранения значения атрибута CKA_PUBLIC_EXPONENT

	CK_BYTE_PTR pbtEncryptedDataOnPKCS11 = NULL_PTR;                      // Указатель на буфер, содержащий зашифрованные в PKCS11 данные
	CK_ULONG ulEncryptedDataOnPKCS11Size = 0;                             // Размер буфера с данными, зашифрованными в PKCS11, в байтах

	CK_BYTE_PTR pbtEncryptedDataOnMSCAPI = NULL_PTR;                      // Указатель на буфер, содержащий зашифрованные в CryptoAPI данные
	CK_ULONG ulEncryptedDataOnMSCAPISize = 0;                             // Размер буфера с данными, зашифрованными в CryptoAPI, в байтах

	CK_BYTE_PTR pbtDecryptedDataMSCAPIToPKCS11 = NULL_PTR;                // Указатель на буфер, содержащий зашифрованные в MS CryptoAPI и расшифрованные в PKCS11 данные
	CK_ULONG ulDecryptedDataMSCAPIToPKCS11Size = 0;                       // Размер буфера с данными, зашифрованными в CryptoAPI и расшифрованными в PKCS11, в байтах

	CK_BYTE_PTR pbtDecryptedDataPKCS11ToPKCS11 = NULL_PTR;                // Указатель на буфер, содержащий зашифрованные в PKCS11 и расшифрованные в PKCS11 данные
	CK_ULONG ulDecryptedDataPKCS11ToPKCS11Size = 0;                       // Размер буфера с данными, зашифрованными в PKCS11 и расшифрованные в PKCS11, в байтах

	DWORD i = 0;                                                          // Вспомогательная переменная-счетчик в циклах
	DWORD dwExponent = 0;
	DWORD dwAllocatedSize = 0;
	DWORD dwDataSize = 0;

	CK_RV rv = CKR_OK;                                                 // Вспомогательная переменная для хранения кода возврата.
	CK_RV rvTemp = CKR_OK;                                             // Вспомогательная переменная для хранения кода возврата

	while (TRUE)
	{
		/************************************************************************
		* Шаг 1: Выполнить действия для начала работы с библиотекой PKCS#11.    *
		************************************************************************/
		printf("Initialization module...\n");
		while (TRUE)
		{
			/**********************************************************************
			* 1.1 Загрузить библиотеку                                            *
			**********************************************************************/
			printf(" Loading library %s", PKCS11_LIBRARY_NAME);  // или PKCS11ECP_LIBRARY_NAME
			hModule = LoadLibrary(PKCS11_LIBRARY_NAME);
			if (hModule == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 1.2 Получить адрес функции запроса структуры с указателями на функции *
			************************************************************************/
			printf(" Getting GetFunctionList function");
			pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule,
			                                                         "C_GetFunctionList");
			if (pfGetFunctionList == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.3 Получить структуру с указателями на функции                     *
			**********************************************************************/
			printf(" Getting function list");
			rv = pfGetFunctionList(&pFunctionList);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.4 Инициализировать библиотеку                                     *
			**********************************************************************/
			printf(" Initializing library");
			rv = pFunctionList->C_Initialize(NULL_PTR);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.5 Получить количество слотов c подключенными токенами             *
			**********************************************************************/
			printf(" Getting number of connected slots");
			rv = pFunctionList->C_GetSlotList(CK_TRUE,
			                                  NULL_PTR,
			                                  &ulSlotCount);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			if (ulSlotCount == 0)
			{
				printf(" No Rutoken is available!\n");
				break;
			}

			aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
			memset(aSlots,
			       0,
			       (ulSlotCount * sizeof(CK_SLOT_ID)));

			/**********************************************************************
			* 1.6 Получить список слотов c подключенными токенами                 *
			**********************************************************************/
			printf(" Getting list of connected slots");
			rv = pFunctionList->C_GetSlotList(CK_TRUE,
			                                  aSlots,
			                                  &ulSlotCount);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			printf(" Slots available: 0x%8.8X\n", (int)ulSlotCount);

			/**********************************************************************
			* 1.7 Открыть RW сессию в первом доступном слоте                      *
			**********************************************************************/
			printf(" Opening Session");
			rv = pFunctionList->C_OpenSession(aSlots[0],
			                                  CKF_SERIAL_SESSION | CKF_RW_SESSION,
			                                  NULL_PTR,
			                                  NULL_PTR,
			                                  &hSession);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.8 Выполнить аутентификацию с правами Пользователя                 *
			**********************************************************************/
			printf(" Logging in");
			rv = pFunctionList->C_Login(hSession,
			                            CKU_USER,
			                            USER_PIN,
			                            sizeof(USER_PIN));
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");
			break;
		}

		if ((rv != CKR_OK) || (ulSlotCount == 0))
		{
			printf("Initialization failed!\n");
			break;
		}
		else
			printf("Initialization has been completed successfully.\n");

#ifdef HAVEMSCRYPTOAPI

		/**********************************************************************
		* Шаг 2: Зашифровать данные по алгоритму RSA с использованием         *
		*        MS CryptoAPI (только для Windows)                            *
		**********************************************************************/
		printf("\nEncrypting by MS CryptoAPI...\n");

		while (TRUE)
		{
			/**********************************************************************
			* 2.1 Получить открытый ключ в формате MS CryptoAPI                   *
			**********************************************************************/
			printf("Retrieving public key in MS CryptoAPI format...\n");
			while (TRUE)
			{
				/************************************************************************
				* Получить массив хэндлов открытых ключей                               *
				************************************************************************/
				printf(" Getting public key...\n");
				FindObjects(hSession,
				            pFunctionList,
				            attrPubKeyFindTempl,
				            arraysize(attrPubKeyFindTempl),
				            &ahKeys,
				            &ulKeysNumber,
				            &rv);
				if (rv != CKR_OK)
					break;

				if (ulKeysNumber == 0)
				{
					printf("\nNo public key found!\n");
					break;
				}

				/************************************************************************
				* Получить значение атрибута CKA_MODULUS                                *
				************************************************************************/
				printf(" Getting modulus value size");
				rv = pFunctionList->C_GetAttributeValue(hSession,
				                                        ahKeys[0],
				                                        &attrModulus,
				                                        1);
				if (rv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				attrModulus.pValue = (CK_BYTE*)malloc(attrModulus.ulValueLen);
				memset(attrModulus.pValue,
				       0,
				       (attrModulus.ulValueLen * sizeof(CK_BYTE)));

				printf(" Getting modulus");
				rv = pFunctionList->C_GetAttributeValue(hSession,
				                                        ahKeys[0],
				                                        &attrModulus,
				                                        1);
				if (rv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				/************************************************************************
				* Получить значение атрибута CKA_PUBLIC_EXPONENT                        *
				************************************************************************/
				printf(" Getting exponent value size");
				rv = pFunctionList->C_GetAttributeValue(hSession,
				                                        ahKeys[0],
				                                        &attrPublicExponent,
				                                        1);
				if (rv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				attrPublicExponent.pValue = (CK_BYTE*)malloc(attrPublicExponent.ulValueLen);
				memset(attrPublicExponent.pValue,
				       0,
				       (attrPublicExponent.ulValueLen * sizeof(CK_BYTE)));

				printf(" Getting exponent");
				rv = pFunctionList->C_GetAttributeValue(hSession,
				                                        ahKeys[0],
				                                        &attrPublicExponent,
				                                        1);
				if (rv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				/************************************************************************
				* Инвертировать порядок байтов в буфере, содержащем значение            *
				* атрибута CKA_MODULUS                                                  *
				************************************************************************/
				for (i = 0;
				     i < (DWORD)(attrModulus.ulValueLen / 2);
				     i++)
				{
					CK_BYTE bTemp = ((CK_BYTE_PTR)attrModulus.pValue)[i];
					((CK_BYTE_PTR)attrModulus.pValue)[i] = ((CK_BYTE_PTR)attrModulus.pValue)[attrModulus.ulValueLen - i - 1];
					((CK_BYTE_PTR)attrModulus.pValue)[attrModulus.ulValueLen - i - 1] = bTemp;
				}

				/************************************************************************
				* Сформировать открытый ключ в формате MS CryptoAPI                     *
				************************************************************************/
				if ((DWORD)attrModulus.ulValueLen % 64 != 0)
					break;

				memset(&blobHeader,
				       0,
				       sizeof(BLOBHEADER));
				memset(&pubKey,
				       0,
				       sizeof(pubKey));

				dwExponent = 0;
				memcpy(&dwExponent,
				       attrPublicExponent.pValue,
				       attrPublicExponent.ulValueLen);

				/************************************************************************
				* Заполнить структуру данных типа BLOBHEADER                            *
				************************************************************************/
				blobHeader.bType = PUBLICKEYBLOB;
				blobHeader.bVersion = CUR_BLOB_VERSION;
				blobHeader.aiKeyAlg = CALG_RSA_KEYX;
				blobHeader.reserved = 0;

				/************************************************************************
				* Заполнить структуру данных типа RSAPUBKEY                            *
				************************************************************************/
				pubKey.bitlen = (DWORD)attrModulus.ulValueLen * 8;
				pubKey.magic = RSAENH_MAGIC_RSA1;
				pubKey.pubexp = dwExponent;

				/************************************************************************
				* Сформировать открытый ключ в формате MS CryptoAPI                     *
				************************************************************************/
				dwCAPIPublicKeySize = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (DWORD)attrModulus.ulValueLen;

				pbtCAPIPublicKey = (BYTE*)malloc(dwCAPIPublicKeySize);
				memset(pbtCAPIPublicKey,
				       0,
				       dwCAPIPublicKeySize);

				memcpy(pbtCAPIPublicKey,
				       &blobHeader,
				       sizeof(BLOBHEADER));

				memcpy(pbtCAPIPublicKey + sizeof(BLOBHEADER),
				       &pubKey,
				       sizeof(RSAPUBKEY));

				memcpy(pbtCAPIPublicKey + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY),
				       (PBYTE)attrModulus.pValue,
				       (DWORD)attrModulus.ulValueLen);
				break;
			}

			if (attrPublicExponent.pValue)
			{
				free(attrPublicExponent.pValue);
				attrPublicExponent.pValue = NULL_PTR;
			}

			if (attrModulus.pValue)
			{
				free(attrModulus.pValue);
				attrModulus.pValue = NULL_PTR;
			}

			if (ahKeys)
			{
				free(ahKeys);
				ahKeys = NULL_PTR;
			}

			if ((rv != CKR_OK) || (ulKeysNumber == 0))
			{
				printf("Cannot retrieve public key in MS format!\n"
				       "Encryption failed!\n");
				break;
			}
			printf("Public key in MS format has been retrieved successfully.\n");

			/**********************************************************************
			* 2.2 Открыть контекст криптопровайдера                               *
			**********************************************************************/
			printf(" Opening MS Enhanced Cryptographic Provider v1.0 context");
			if (CryptAcquireContext(&hProv,
			                        NULL,
			                        MS_ENHANCED_PROV,
			                        PROV_RSA_FULL,
			                        CRYPT_VERIFYCONTEXT)
			    != TRUE)
			{
				printf(" -> Failed\n"
				       "\n\nEncryption failed!\n\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 2.3 Импортировать открытый ключ в контекст криптопровайдера         *
			**********************************************************************/
			printf(" Importing public key");
			if (CryptImportKey(hProv,
			                   pbtCAPIPublicKey,
			                   dwCAPIPublicKeySize,
			                   NULL_PTR,
			                   0,
			                   &hKey)
			    != TRUE)
			{
				printf(" -> Failed\n");
				printf("\n\nEncryption failed!\n\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 2.4 Зашифровать открытый текст                                      *
			**********************************************************************/
			printf(" Getting encrypted data size");
			if (CryptEncrypt(hKey,
			                 NULL_PTR,
			                 TRUE,
			                 0,
			                 NULL,
			                 &ulEncryptedDataOnMSCAPISize,
			                 0)
			    != TRUE)
			{
				printf(" -> Failed\n");
				printf("\n\nEncryption failed!\n\n");
				break;
			}
			printf(" -> OK\n");

			pbtEncryptedDataOnMSCAPI = (CK_BYTE*)malloc(ulEncryptedDataOnMSCAPISize);
			memset(pbtEncryptedDataOnMSCAPI,
			       0,
			       (ulEncryptedDataOnMSCAPISize * sizeof(CK_BYTE)));

			memcpy(pbtEncryptedDataOnMSCAPI,
			       pbtData,
			       (arraysize(pbtData) * sizeof(CK_BYTE)));

			dwAllocatedSize = ulEncryptedDataOnMSCAPISize;
			dwDataSize = arraysize(pbtData);

			printf(" Encrypting data");
			if (CryptEncrypt(hKey,
			                 NULL_PTR,
			                 TRUE,
			                 0,
			                 pbtEncryptedDataOnMSCAPI,
			                 &dwDataSize,
			                 dwAllocatedSize)
			    != TRUE)
			{
				printf(" -> Failed\n");
				printf("\n\nEncryption failed!\n\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 2.5 Инвертировать порядок байтов в буфере, содержащем шифротекст      *
			************************************************************************/
			for (i = 0;
			     i < (ulEncryptedDataOnMSCAPISize / 2);
			     i++)
			{
				CK_BYTE bTemp = pbtEncryptedDataOnMSCAPI[i];
				pbtEncryptedDataOnMSCAPI[i] = pbtEncryptedDataOnMSCAPI[ulEncryptedDataOnMSCAPISize - i - 1];
				pbtEncryptedDataOnMSCAPI[ulEncryptedDataOnMSCAPISize - i - 1] = bTemp;
			}

			/************************************************************************
			* 2.6 Распечатать буфер, содержащий шифротекст                          *
			************************************************************************/
			printf("Encrypted buffer text: ");
			for (i = 0;
			     i < ulEncryptedDataOnMSCAPISize;
			     i++)
			{
				if (i % 8 == 0)
					printf("\n");
				printf("%02X ", pbtEncryptedDataOnMSCAPI[i]);
			}

			printf("\nEncryption has been completed successfully.\n");
			break;
		}

		if (hKey)
		{
			CryptDestroyKey(hKey);
			hKey = NULL_PTR;
		}
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			hProv = NULL_PTR;
		}

		if (pbtCAPIPublicKey)
		{
			free(pbtCAPIPublicKey);
			pbtCAPIPublicKey = NULL_PTR;
		}

#endif

		/**********************************************************************
		* Шаг 3: Зашифровать данные по алгоритму RSA с использованием PKCS11. *
		**********************************************************************/
		printf("\nEncrypting by PKCS11...\n");
		while (TRUE)
		{
			/************************************************************************
			* 3.1 Получить массив хэндлов 
			открытых ключей                           *
			************************************************************************/
			printf(" Getting public key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrPubKeyFindTempl,
			            arraysize(attrPubKeyFindTempl),
			            &ahKeys,
			            &ulKeysNumber,
			            &rv);
			if (rv != CKR_OK)
				break;

			if (ulKeysNumber == 0)
			{
				printf("\nNo public key found!\n");
				break;
			}

			/**********************************************************************
			* 3.2 Инициализировать операцию шифрования                            *
			**********************************************************************/
			printf(" C_EncryptInit");
			rv = pFunctionList->C_EncryptInit(hSession,
			                                  &ckmEncDecMech,
			                                  ahKeys[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 3.3 Зашифровать открытый текст                                      *
			**********************************************************************/
			printf(" Getting encrypted data size");
			rv = pFunctionList->C_Encrypt(hSession,
			                              pbtData,
			                              arraysize(pbtData),
			                              NULL_PTR,
			                              &ulEncryptedDataOnPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtEncryptedDataOnPKCS11 = (CK_BYTE*)malloc(ulEncryptedDataOnPKCS11Size);
			memset(pbtEncryptedDataOnPKCS11,
			       0,
			       (ulEncryptedDataOnPKCS11Size * sizeof(CK_BYTE)));

			printf(" C_Encrypt");
			rv = pFunctionList->C_Encrypt(hSession,
			                              pbtData,
			                              arraysize(pbtData),
			                              pbtEncryptedDataOnPKCS11,
			                              &ulEncryptedDataOnPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 3.4 Распечатать буфер, содержащий шифротекст                          *
			************************************************************************/
			printf("Encrypted buffer is:");
			for (i = 0;
			     i < ulEncryptedDataOnPKCS11Size;
			     i++)
			{
				if (i % 8 == 0)
					printf("\n");
				printf("%02X ", pbtEncryptedDataOnPKCS11[i]);
			}
			break;
		}

		if (ahKeys)
		{
			free(ahKeys);
			ahKeys = NULL_PTR;
		}

		if ((rv != CKR_OK) || (ulKeysNumber == 0))
		{
			printf("Encryption failed!\n");
			break;
		}
		printf("\nEncryption has been completed successfully.\n\n");

#ifdef HAVEMSCRYPTOAPI

		/***********************************************************************
		* Шаг 4: Расшифровать по алгоритму RSA данные, ранее зашифрованные     *
		*        на MS CryptoAPI, с использованием PKCS#11 (только для Windows)*
		***********************************************************************/
		printf("Decrypting data, previously encrypted by MS CryptoAPI, by PKCS#11...\n");
		while (TRUE)
		{
			/************************************************************************
			* 4.1 Получить массив хэндлов открытых ключей                           *
			************************************************************************/
			printf(" Getting private key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrPrivKeyFindTempl,
			            arraysize(attrPrivKeyFindTempl),
			            &ahKeys,
			            &ulKeysNumber,
			            &rv);
			if (rv != CKR_OK)
				break;

			if (ulKeysNumber == 0)
			{
				printf("No private key found!!!\n");
				break;
			}

			/**********************************************************************
			* 4.2 Инициализировать операцию расшифрования                         *
			**********************************************************************/
			printf(" C_DecryptInit");
			rv = pFunctionList->C_DecryptInit(hSession,
			                                  &ckmEncDecMech,
			                                  ahKeys[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 4.3 Расшифровать шифротекст                                             *
			**********************************************************************/
			printf(" Getting decrypted data size");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedDataOnMSCAPI,
			                              ulEncryptedDataOnMSCAPISize,
			                              NULL_PTR,
			                              &ulDecryptedDataMSCAPIToPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtDecryptedDataMSCAPIToPKCS11 = (CK_BYTE*)malloc(ulDecryptedDataMSCAPIToPKCS11Size);
			memset(pbtDecryptedDataMSCAPIToPKCS11,
			       0,
			       (ulDecryptedDataMSCAPIToPKCS11Size * sizeof(CK_BYTE)));

			printf(" C_Decrypt");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedDataOnMSCAPI,
			                              ulEncryptedDataOnMSCAPISize,
			                              pbtDecryptedDataMSCAPIToPKCS11,
			                              &ulDecryptedDataMSCAPIToPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 4.4 Распечатать буфер, содержащий расшифрованный текст                *
			************************************************************************/
			printf("Decrypted buffer is:");
			for (i = 0;
			     i < ulDecryptedDataMSCAPIToPKCS11Size;
			     i++)
			{
				if (i % 8 == 0)
					printf("\n");
				printf("%02X ", pbtDecryptedDataMSCAPIToPKCS11[i]);
			}
			break;
		}

		if (ahKeys)
		{
			free(ahKeys);
			ahKeys = NULL_PTR;
		}

		if ((rv != CKR_OK) || (ulKeysNumber == 0))
		{
			printf("\nDecryption failed!\n\n");
			break;
		}
		printf("\nDecryption has been completed successfully.\n\n");

		/**********************************************************************
		* Шаг 5: Сравнить исходные данные с расшифрованными.                  *
		**********************************************************************/
		if ((ulDecryptedDataMSCAPIToPKCS11Size != arraysize(pbtData))
		    || memcmp(pbtData,
		              pbtDecryptedDataMSCAPIToPKCS11,
		              ulDecryptedDataMSCAPIToPKCS11Size) != 0)
		{
			printf("\n\nThe decrypted and the plain text are different!!!\n\n");
			break;
		}
		printf("The decrypted and the plain text are equal.\n");

#endif

		/**********************************************************************
		* Шаг 6: Расшифровать по алгоритму RSA данные, ранее зашифрованные    *
		*        на PKCS#11, с использованием PKCS#11.                        *
		**********************************************************************/
		printf("\nDecrypting data, previously encrypted by PKCS#11, by PKCS#11...\n");
		while (TRUE)
		{
			/************************************************************************
			* 6.1 Получить массив хэндлов открытых ключей                           *
			************************************************************************/
			printf(" Getting private key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrPrivKeyFindTempl,
			            arraysize(attrPrivKeyFindTempl),
			            &ahKeys,
			            &ulKeysNumber,
			            &rv);
			if (rv != CKR_OK)
				break;

			if (ulKeysNumber == 0)
			{
				printf("No private key found!!!\n");
				break;
			}

			/**********************************************************************
			* 6.2 Инициализировать операцию расшифрования                         *
			**********************************************************************/
			printf(" C_DecryptInit");
			rv = pFunctionList->C_DecryptInit(hSession,
			                                  &ckmEncDecMech,
			                                  ahKeys[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 6.3 Расшифровать шифротекст                                         *
			**********************************************************************/
			printf(" Getting decrypted data size");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedDataOnPKCS11,
			                              ulEncryptedDataOnPKCS11Size,
			                              NULL_PTR,
			                              &ulDecryptedDataPKCS11ToPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtDecryptedDataPKCS11ToPKCS11 = (CK_BYTE*)malloc(ulDecryptedDataPKCS11ToPKCS11Size);
			memset(pbtDecryptedDataPKCS11ToPKCS11,
			       0,
			       (ulDecryptedDataPKCS11ToPKCS11Size * sizeof(CK_BYTE)));

			printf(" C_Decrypt");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedDataOnPKCS11,
			                              ulEncryptedDataOnPKCS11Size,
			                              pbtDecryptedDataPKCS11ToPKCS11,
			                              &ulDecryptedDataPKCS11ToPKCS11Size);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 6.4 Распечатать буфер, содержащий расшифрованный текст                *
			************************************************************************/
			printf("Decrypted buffer is:");
			for (i = 0;
			     i < ulDecryptedDataPKCS11ToPKCS11Size;
			     i++)
			{
				if (i % 8 == 0)
					printf("\n");
				printf("%02X ", pbtDecryptedDataPKCS11ToPKCS11[i]);
			}
			break;
		}

		if (ahKeys)
		{
			free(ahKeys);
			ahKeys = NULL_PTR;
		}

		if ((rv != CKR_OK) || (ulKeysNumber == 0))
		{
			printf("\nDecryption failed!\n\n");
			break;
		}
		printf("\nDecryption has been completed successfully.\n\n");
		/**********************************************************************
		* Шаг 7: Сравнить исходные данные с расшифрованными.                  *
		**********************************************************************/
		if ((ulDecryptedDataPKCS11ToPKCS11Size != arraysize(pbtData))
		    || memcmp(pbtData,
		              pbtDecryptedDataPKCS11ToPKCS11,
		              ulDecryptedDataPKCS11ToPKCS11Size) != 0)
		{
			printf("\n\nThe decrypted and the plain text are different!!!\n\n");
			break;
		}
		printf("The decrypted and the plain text are equal.\n");
		break;
	}

	/**********************************************************************
	* Шаг 8: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");

	if (hSession)
	{
		/**********************************************************************
		* 8.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 8.2 Закрыть все открытые сессии в слоте                             *
		**********************************************************************/
		printf(" C_CloseAllSession");
		rvTemp = pFunctionList->C_CloseAllSessions(aSlots[0]);
		if (rvTemp != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hSession = NULL_PTR;
	}

	if (pFunctionList)
	{
		/**********************************************************************
		* 8.3 Деинициализировать библиотеку                                   *
		**********************************************************************/
		printf(" Finalizing library");
		rvTemp = pFunctionList->C_Finalize(NULL_PTR);
		if (rvTemp != CKR_OK)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		pFunctionList = NULL_PTR;
	}

	if (hModule)
	{
		/**********************************************************************
		* 8.4 Выгрузить библиотеку из памяти                                  *
		**********************************************************************/
		printf(" Unloading");
		if (FreeLibrary(hModule) != TRUE)
			printf(" -> Failed\n");
		else
			printf(" -> OK\n");
		hModule = NULL_PTR;
	}

	if (rvTemp != CKR_OK)
		printf("Unloading failed!\n\n");
	else
		printf("Unloading has been completed successfully.\n\n");

	if (pbtEncryptedDataOnMSCAPI)
	{
		free(pbtEncryptedDataOnMSCAPI);
		pbtEncryptedDataOnMSCAPI = NULL_PTR;
	}

	if (pbtEncryptedDataOnPKCS11)
	{
		free(pbtEncryptedDataOnPKCS11);
		pbtEncryptedDataOnPKCS11 = NULL_PTR;
	}
	if (pbtDecryptedDataMSCAPIToPKCS11)
	{
		free(pbtDecryptedDataMSCAPIToPKCS11);
		pbtDecryptedDataMSCAPIToPKCS11 = NULL_PTR;
	}
	if (pbtDecryptedDataPKCS11ToPKCS11)
	{
		free(pbtDecryptedDataPKCS11ToPKCS11);
		pbtDecryptedDataPKCS11ToPKCS11 = NULL_PTR;
	}

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if ((rv != CKR_OK) || (ulSlotCount == 0) || (ulKeysNumber == 0))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");


	getchar();
	return rv != CKR_OK;
}
