/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд шифрования/расшифрования на ключе ГОСТ 28147-89:  *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - шифрование сообщения на демонстрационном ключе;                     *
*  - расшифрование зашифрованнного сообщения на демонстрационном ключе;  *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Пример использует объекты, созданные в памяти Рутокен примером         *
* CreateGOST28147-89.                                                    *
*************************************************************************/

#include "Common.h"

/* Шаблон для поиска симметричного ключа ГОСТ 28147-89 */

CK_ATTRIBUTE attrGOST28147_89SecKeySearchTmpl[] =
{
	{ CKA_ID, &SecKeyIDGOST, sizeof(SecKeyIDGOST) - 1}
};

/* Данные для шифрования */
CK_BYTE pbtData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	                  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
					  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
					  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
					  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00 };

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
	CK_RV rvTemp = CKR_OK;      // Вспомогательная переменная для хранения кода возврата
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
	HMODULE hModule = NULL_PTR;                           // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;        // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;    // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                     // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                             // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE_PTR ahKeys = NULL_PTR;               // Указатель на массив хэндлов ключей, соответствующих критериям поиска
	CK_ULONG ulKeysNumber = 0;                            // Количество хэндлов ключей в массиве

	CK_BYTE_PTR pbtEncryptedData = NULL_PTR;              // Указатель на буфер, содержащий зашифрованные данные
	CK_ULONG ulEncryptedDataSize = 0;                     // Размер буфера с зашифрованными данными, в байтах
	CK_BYTE_PTR pbtDecryptedData = NULL_PTR;              // Указатель на буфер, содержащий расшифрованные данные
	CK_ULONG ulDecryptedDataSize = 0;                     // Размер буфера с расшифрованными данными, в байтах
	CK_ULONG ulBlockSize = 0;							  // Размер блока данных, в байтах
	CK_ULONG ulCurrentPosition = 0;						  // Текущее начало блока
	CK_ULONG ulRestLen = 0;						          // Размер оставшегося буфера

	CK_RV rv = CKR_OK;                                    // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                // Вспомогательная переменная для хранения кода возврата

	DWORD i = 0;                                          // Вспомогательная переменная-счетчик в циклах

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
			printf(" Loading library %s", PKCS11ECP_LIBRARY_NAME);
			hModule = LoadLibrary(PKCS11ECP_LIBRARY_NAME);
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
				printf(" No Rutoken ECP is available!\n");
				break;
			}

			aSlots = (CK_SLOT_ID*)malloc(sizeof(ulSlotCount));
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
			printf("Initialization has been completed successfully.\n\n");

		/**********************************************************************
		* Шаг 2: Зашифровать данные по алгоритму ГОСТ 28147-89                *
		**********************************************************************/
		printf("Encrypting...\n");
		while (TRUE)
		{
			/************************************************************************
			* 2.1 Получить массив хэндлов секретных ключей                          *
			************************************************************************/
			printf(" Getting secret key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrGOST28147_89SecKeySearchTmpl,
			            arraysize(attrGOST28147_89SecKeySearchTmpl),
			            &ahKeys,
			            &ulKeysNumber,
			            &rv);
			if (rv != CKR_OK)
				break;
			if (ulKeysNumber == 0)
			{
				printf("No secret key found!\n");
				break;
			}

			/**********************************************************************
			* 2.2 Инициализировать операцию шифрования                            *
			**********************************************************************/
			printf(" C_EncryptInit");
			rv = pFunctionList->C_EncryptInit(hSession,
			                                  &ckmEncDecGOSTMech2,
			                                  ahKeys[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 2.3 Зашифровать открытый текст                                      *
			**********************************************************************/
			ulEncryptedDataSize = arraysize(pbtData);
			ulRestLen = arraysize(pbtData);
			pbtEncryptedData = (CK_BYTE*)malloc(ulEncryptedDataSize);
			memset(pbtEncryptedData,
				0,
				(ulEncryptedDataSize * sizeof(CK_BYTE)));

			while (ulRestLen)
			{
				ulBlockSize = 32; //Поддерживаются блоки кратные 32 байтам

				if (ulBlockSize > ulRestLen)
					ulBlockSize = ulRestLen;

				printf("Block size: %u B (Total: %u of %u) ", ulBlockSize, ulCurrentPosition + ulBlockSize, ulEncryptedDataSize);
				rv = pFunctionList->C_EncryptUpdate(hSession,
													pbtData + ulCurrentPosition,
													ulBlockSize,
													pbtEncryptedData + ulCurrentPosition,
													&ulBlockSize);
				if (rv != CKR_OK)
				{
					printf(" -> Failed\n");
					break;
				}
				printf(" -> OK\n");

				ulCurrentPosition += ulBlockSize;
				ulRestLen -= ulBlockSize;
			}

			if (rv != CKR_OK)
				break;

			printf("Finalizing encryption");
			rv = pFunctionList->C_EncryptFinal( hSession, 
												NULL_PTR,
												&ulEncryptedDataSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 2.4 Распечатать буфер, содержащий шифротекст                          *
			************************************************************************/
			printf("Encrypted buffer is:\n");
			for (i = 0;
			     i < ulEncryptedDataSize;
			     i++)
			{
				printf("%02X ", pbtEncryptedData[i]);
				if ((i + 1) % 8 == 0)
					printf("\n");
			}
			break;
		}

		if ((rv != CKR_OK) || (ulKeysNumber == 0))
		{
			printf("\nEncryption failed!\n");
			break;
		}
		printf("\nEncryption has been completed successfully.\n\n");

		if (ahKeys)
		{
			free(ahKeys);
			ahKeys = NULL_PTR;
		}
		/**********************************************************************
		* Шаг 3: Расшифровать по алгоритму  данные                            *
		**********************************************************************/
		printf("\nDecrypting data...\n");
		while (TRUE)
		{
			/************************************************************************
			* 3.1 Получить массив хэндлов секретных ключей                          *
			************************************************************************/
			printf(" Getting secret key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrGOST28147_89SecKeySearchTmpl,
			            arraysize(attrGOST28147_89SecKeySearchTmpl),
			            &ahKeys,
			            &ulKeysNumber,
			            &rv);
			if (rv != CKR_OK)
				break;
			if (ulKeysNumber == 0)
			{
				printf("No secret key found!\n");
				break;
			}

			/**********************************************************************
			* 3.2 Инициализировать операцию расшифрования                         *
			**********************************************************************/
			printf(" C_DecryptInit");
			rv = pFunctionList->C_DecryptInit(hSession,
			                                  &ckmEncDecGOSTMech2,
			                                  ahKeys[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 3.3 Расшифровать шифротекст                                         *
			**********************************************************************/
			printf(" Getting decrypted data size");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedData,
			                              ulEncryptedDataSize,
			                              NULL_PTR,
			                              &ulDecryptedDataSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtDecryptedData = (CK_BYTE*)malloc(ulDecryptedDataSize);
			memset(pbtDecryptedData,
			       0,
			       (ulDecryptedDataSize * sizeof(CK_BYTE)));

			printf(" C_Decrypt");
			rv = pFunctionList->C_Decrypt(hSession,
			                              pbtEncryptedData,
			                              ulEncryptedDataSize,
			                              pbtDecryptedData,
			                              &ulDecryptedDataSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 3.4 Распечатать буфер, содержащий расшифрованный текст                *
			************************************************************************/
			printf("Decrypted buffer is:\n");
			for (i = 0;
			     i < ulDecryptedDataSize;
			     i++)
			{
				printf("%02X ", pbtDecryptedData[i]);
				if ((i + 1) % 8 == 0)
					printf("\n");
			}
			break;
		}

		if ((rv != CKR_OK) || (ulKeysNumber == 0))
		{

			printf("\nDecryption failed!\n");
			break;
		}
		printf("\nDecryption has been completed successfully.\n");

		if (ahKeys)
		{
			free(ahKeys);
			ahKeys = NULL_PTR;
		}

		/**********************************************************************
		* Шаг 4: Сравнить исходные данные с расшифрованными.                  *
		**********************************************************************/
		if ((ulDecryptedDataSize != arraysize(pbtData))
		    || memcmp(pbtData,
		              pbtDecryptedData,
		              ulDecryptedDataSize) != 0)
		{
			printf("\n\nThe decrypted and the plain text are different!!!\n\n");
			break;
		}
		else
			printf("\nThe decrypted and the plain text are equal.\n");
		break;
	}

	/**********************************************************************
	* Шаг 5: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");
	if (hSession)
	{
		/**********************************************************************
		* 5.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 5.2 Закрыть все открытые сессии в слоте                             *
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
		* 5.3 Деинициализировать библиотеку                                   *
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
		* 5.4 Выгрузить библиотеку из памяти                                  *
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

	if (pbtEncryptedData)
	{
		free(pbtEncryptedData);
		pbtEncryptedData = NULL_PTR;
	}

	if (pbtDecryptedData)
	{
		free(pbtDecryptedData);
		pbtDecryptedData = NULL_PTR;
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
