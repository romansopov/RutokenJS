/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд вычисления/проверки ЭП на ключах ГОСТ 34.10-2001: *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - подпись сообщения на демонстрационном ключе;                        *
*  - проверка подписи на демонстрационном ключе;                         *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Пример использует объекты, созданные в памяти Рутокен примером         *
* CreateGOST34.10-2001.                                                  *
*************************************************************************/

#include "Common.h"

/* Данные для подписи */
CK_BYTE pbtData[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

/* Шаблон для поиска ГОСТ Р 34.10-2001 пары для проверки подписи */
CK_ATTRIBUTE attrGOST34_10_2001VerifierTempl[] =
{
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey)}
};

/* Шаблон для поиска ГОСТ Р 34.10-2001 пары для подписи */
CK_ATTRIBUTE attrGOST34_10_2001SignerTempl[] =
{
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey)}
};

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
	CK_RV rvTemp = CKR_OK;       // Вспомогательная переменная для хранения кода возврата
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

/**********************************************************************
* Сформировать хеш от исходных данных                                 *
**********************************************************************/
BOOL HashData(IN CK_SESSION_HANDLE hSession,                // Хэндл открытой сессии
              IN CK_FUNCTION_LIST_PTR pFunctionList,        // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
              IN CK_MECHANISM_PTR pHashMechanism,           // Указатель на механизм хеширования данных
              IN CK_BYTE_PTR pbtDataToHash,                 // Указатель на буфер с данными для хеширования
              IN CK_ULONG ulDataToHashSize,                 // Размер буфера с данными для хеширования в байтах
              OUT CK_BYTE_PTR* ppbtHash,                    // Указатель на буфер, в который будут помещены хешированные данные
              OUT CK_ULONG* pulHashSize,                    // Размер буфера, в который будут помещены хешированные данные, в байтах
              OUT CK_RV* prv                                // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
              )
{
	DWORD i = 0;               // Вспомогательная переменная. Счетчик цикла
	*ppbtHash = NULL_PTR;
	*pulHashSize = 0;

	printf(" Hashing data...\n");
	while (TRUE)
	{
		/**********************************************************************
		* Инициализировать операцию хеширования                               *
		**********************************************************************/
		printf("  C_DigestInit");
		*prv = pFunctionList->C_DigestInit(hSession,
		                                   pHashMechanism);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* Определить размер хешированных данных                               *
		**********************************************************************/
		printf("  C_Digest step 1");
		*prv = pFunctionList->C_Digest(hSession,
		                               pbtDataToHash,
		                               ulDataToHashSize,
		                               *ppbtHash,
		                               pulHashSize);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		*ppbtHash = (CK_BYTE*)malloc(*pulHashSize);
		memset(*ppbtHash,
		       0,
		       (*pulHashSize * sizeof(CK_BYTE)));

		/**********************************************************************
		* Сформировать хеш от исходных данных                                 *
		**********************************************************************/
		printf("  C_Digest step 2");
		*prv = pFunctionList->C_Digest(hSession,
		                               pbtDataToHash,
		                               ulDataToHashSize,
		                               *ppbtHash,
		                               pulHashSize);
		if (*prv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/************************************************************************
		* Распечатать буфер, содержащий хешированные данные                     *
		************************************************************************/
		printf(" Hashed buffer is: \n");
		for (i = 0;
		     i < *pulHashSize;
		     i++)
		{
			printf(" %02X", (*ppbtHash)[i]);
			if ((i + 1) % 8 == 0)
				printf("\n");
		}
		break;
	}

	if ((*prv != CKR_OK) && (*ppbtHash))
	{
		free(*ppbtHash);
		*ppbtHash = NULL_PTR;
		*pulHashSize = 0;
	}

	if (*prv == CKR_OK)
		printf(" Hashing has been completed.\n");
	else
		printf("\n\n Hashing failed!\n\n");

	return *prv == CKR_OK;
}


/************************************************************************
* main()                                                                *
************************************************************************/
int main(void)
{
	HMODULE hModule = NULL_PTR;                          // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;               // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;   // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                    // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                            // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE_PTR phObject = NULL_PTR;            // Указатель на массив хэндлов объектов, соответствующих критериям поиска
	CK_ULONG ulObjectCount = 0;                          // Количество хэндлов объектов в массиве

	CK_BYTE_PTR pbtSignature = NULL_PTR;                 // Указатель на буфер, содержащий подпись для исходных данных
	CK_ULONG ulSignatureSize = 0;                        // Размер буфера, содержащего подпись для исходных данных, в байтах

	CK_BYTE_PTR pbHash = NULL_PTR;                       // Указатель на временный буфер для хешированных данных
	CK_ULONG ulHashSize = 0;                             // Размер временного буфера в байтах

	CK_RV rv = CKR_OK;                                   // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                               // Вспомогательная переменная для хранения кода возврата

	DWORD i = 0;                                         // Вспомогательная переменная-счетчик в циклах

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

		/**********************************************************************
		* Шаг 2: Выполнить подпись данных по алгоритму ГОСТ Р 34.10-2001.     *
		**********************************************************************/
		printf("\nSigning data...\n");
		while (TRUE)
		{
			/************************************************************************
			* 2.1 Получить массив хэндлов закрытых ключей                           *
			************************************************************************/
			printf(" Getting signing key...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrGOST34_10_2001SignerTempl,
			            arraysize(attrGOST34_10_2001SignerTempl),
			            &phObject,
			            &ulObjectCount,
			            &rv);
			if (rv != CKR_OK)
				break;

			if (ulObjectCount == 0)
			{
				printf("\nNo signature key found!\n");
				break;
			}

			/**********************************************************************
			* 2.2 Сформировать хеш от исходных данных                             *
			**********************************************************************/
			HashData(hSession,
			         pFunctionList,
			         &ckmGOST34_11_94Mech,
			         pbtData,
			         arraysize(pbtData),
			         &pbHash,
			         &ulHashSize,
			         &rv);
			if (rv != CKR_OK)
				break;

			/**********************************************************************
			* 2.3 Инициализировать операцию подписи данных                        *
			**********************************************************************/
			printf(" C_SignInit");
			rv = pFunctionList->C_SignInit(hSession,
			                               &ckmGOST_34_10_2001SigVerMech,
			                               phObject[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 2.4 Определить размер зашифрованных данных                          *
			**********************************************************************/
			printf(" C_Sign step 1");
			rv = pFunctionList->C_Sign(hSession,
			                           pbHash,
			                           ulHashSize,
			                           pbtSignature,
			                           &ulSignatureSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			pbtSignature = (CK_BYTE*)malloc(ulSignatureSize);
			memset(pbtSignature,
			       0,
			       ulSignatureSize * sizeof(CK_BYTE));

			/**********************************************************************
			* 2.5 Подписать исходные данные                                       *
			**********************************************************************/
			printf(" C_Sign step 2");
			rv = pFunctionList->C_Sign(hSession,
			                           pbHash,
			                           ulHashSize,
			                           pbtSignature,
			                           &ulSignatureSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/************************************************************************
			* 2.6 Распечатать буфер, содержащий подпись                             *
			************************************************************************/
			printf("Signature buffer is: \n");
			for (i = 0;
			     i < ulSignatureSize;
			     i++)
			{
				printf("%02X ", pbtSignature[i]);
				if ((i + 1) % 8 == 0)
					printf("\n");
			}
			break;
		}

		if (pbHash)
		{
			free(pbHash);
			pbHash = NULL_PTR;
		}

		if ((rv != CKR_OK) && (pbtSignature))
		{
			free(pbtSignature);
			pbtSignature = NULL_PTR;
			ulSignatureSize = 0;
		}

		if ((rv != CKR_OK) || (ulObjectCount == 0))
		{
			printf("\nSigning operation failed!\n");
			break;
		}
		else
			printf("\nData has been signed successfully.\n");

		if (phObject)
		{
			free(phObject);
			ulObjectCount = 0;
			phObject = NULL_PTR;
		}

		/**********************************************************************
		* Шаг 3: Выполнить проверку подписи данных                            *
		*        по алгоритму ГОСТ Р 34.10-2001.                              *
		**********************************************************************/
		printf("\nVerifying signature...\n");
		while (TRUE)
		{
			/************************************************************************
			* 3.1 Получить массив хэндлов открытых ключей                           *
			************************************************************************/
			printf(" Getting key to verify...\n");
			FindObjects(hSession,
			            pFunctionList,
			            attrGOST34_10_2001VerifierTempl,
			            arraysize(attrGOST34_10_2001VerifierTempl),
			            &phObject,
			            &ulObjectCount,
			            &rv);
			if (rv != CKR_OK)
				break;

			if (ulObjectCount == 0)
			{
				printf("\nNo verification key found!\n");
				break;
			}

			/**********************************************************************
			* 3.2 Сформировать хеш от исходных данных                             *
			**********************************************************************/
			HashData(hSession,
			         pFunctionList,
			         &ckmGOST34_11_94Mech,
			         pbtData,
			         arraysize(pbtData),
			         &pbHash,
			         &ulHashSize,
			         &rv);

			if (rv != CKR_OK)
				break;

			/**********************************************************************
			* 3.3 Инициализировать операцию проверки подписи                      *
			**********************************************************************/
			printf(" C_VerifyInit");
			rv = pFunctionList->C_VerifyInit(hSession,
			                                 &ckmGOST_34_10_2001SigVerMech,
			                                 phObject[0]);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 3.4 Проверить подпись для исходных данных                           *
			**********************************************************************/
			printf(" C_Verify");
			rv = pFunctionList->C_Verify(hSession,
			                             pbHash,
			                             ulHashSize,
			                             pbtSignature,
			                             ulSignatureSize);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");
			break;
		}

		if (pbtSignature)
		{
			free(pbtSignature);
			pbtSignature = NULL_PTR;
		}

		if ((rv != CKR_OK) || (ulObjectCount == 0))
		{
			printf("\nVerifying failed!\n\n");
			break;
		}
		else
			printf("\nVerifying has been completed successfully.\n");
		break;
	}

	/**********************************************************************
	* Шаг 4: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");
	rvTemp = CKR_OK;
	if (hSession)
	{
		/**********************************************************************
		* 4.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 4.2 Закрыть все открытые сессии в слоте                             *
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
		* 4.3 Деинициализировать библиотеку                                   *
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
		* 4.4 Выгрузить библиотеку из памяти                                  *
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

	if (phObject)
	{
		free(phObject);
		phObject = NULL_PTR;
	}

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if ((rv != CKR_OK) || (ulSlotCount == 0) || (ulObjectCount == 0))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}
