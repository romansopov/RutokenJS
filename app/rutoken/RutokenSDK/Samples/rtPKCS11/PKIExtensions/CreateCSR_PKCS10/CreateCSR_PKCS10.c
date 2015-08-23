/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C   *
*------------------------------------------------------------------------*
* Использование команды создания запроса на сертификат ключа подписи для * 
* ключевой пары ГОСТ 34.10-2001:										 *
*  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
*  - выполнение аутентификации c правами Пользователя;					 *
*  - генерация ключевой пары ГОСТ 34.10-2001 на Рутокен;                 *
*  - создание подписанного запроса на сертификат для сгенерированной	 *
*    ключевой пары и его вывод;										     *
*  - удаление созданных объектов;										 *
*  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
*    соединения с Рутокен PINPad.                                        *
*------------------------------------------------------------------------*
* Пример самодостаточен.		                                         *
*************************************************************************/

#include "Common.h"

/************************************************************************
* Шаблон для создания открытого ключа ГОСТ Р 34.10-2001		            *
************************************************************************/
CK_ATTRIBUTE PublicKeyTmpl[] =
{
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey)},                      // Объект открытого ключа ГОСТ Р 34.10-2001 (#1)
	{ CKA_LABEL, &PubLabelGOST1, sizeof(PubLabelGOST1) - 1},        // Метка ключа
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},         // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktGOST34_10_2001, sizeof(ktGOST34_10_2001)},   // Тип ключа
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Ключ доступен без авторизации на токене
	{ CKA_GOSTR3410_PARAMS, &GOST3410_params_oid, sizeof(GOST3410_params_oid)}, // Параметры алгоритма ГОСТ Р 34.10-2001
};

/************************************************************************
* Шаблон для создания закрытого ключа ГОСТ Р 34.10-2001                 *
************************************************************************/
CK_ATTRIBUTE PrivateKeyTmpl[] =
{
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey)},                    // Объект закрытого ключа ГОСТ Р 34.10-2001 (#1)
	{ CKA_LABEL, &PrivLabelGOST1, sizeof(PrivLabelGOST1) - 1},      // Метка ключа
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},         // Идентификатор ключевой пары #1 (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktGOST34_10_2001, sizeof(ktGOST34_10_2001)},   // Тип ключа
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_PRIVATE, &bTrue, sizeof(bTrue)},                          // Ключ доступен только после авторизации на токене
	{ CKA_DERIVE, &bTrue, sizeof(bTrue)},                           // Ключ поддерживает деривацию (из него могут быть получены другие ключи)
	{ CKA_GOSTR3410_PARAMS, GOST3410_params_oid, sizeof(GOST3410_params_oid)}, // Параметры алгоритма ГОСТ Р 34.10-2001
};

/************************************************************************
* Список полей DN (Distinguished Name)								    *
************************************************************************/
CK_CHAR_PTR dn[] = 	{	(CK_CHAR_PTR)"CN",						// Тип поля CN (Common Name)
						(CK_CHAR_PTR)"Ivanoff",					// Значение
						(CK_CHAR_PTR)"C",						// Тип поля C (Country)
						(CK_CHAR_PTR)"RU",	
						(CK_CHAR_PTR)"2.5.4.5",					// Тип поля SN (Serial Number)
						(CK_CHAR_PTR)"12312312312",
						(CK_CHAR_PTR)"1.2.840.113549.1.9.1",	// Тип поля E (E-mail)
						(CK_CHAR_PTR)"ivanov@mail.ru",
						(CK_CHAR_PTR)"ST",						// Тип поля ST (State or province)
						(CK_CHAR_PTR)"Moscow",
};

/************************************************************************
* Список дополнительных полей										    *
************************************************************************/
CK_CHAR_PTR exts[] = {  (CK_CHAR_PTR)"keyUsage",
						(CK_CHAR_PTR)"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
						(CK_CHAR_PTR)"extendedKeyUsage",
						(CK_CHAR_PTR)"1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
};

/************************************************************************
* main()                                                                *
************************************************************************/
int main(void)
{
	HMODULE hModule = NULL_PTR;                          // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;               // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;   // Указатель на функцию C_GetFunctionList

	CK_FUNCTION_LIST_EXTENDED_PTR pFunctionListEx = NULL_PTR;        // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
	CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = NULL_PTR;  // Указатель на функцию C_EX_GetFunctionListExtended

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                    // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                            // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE hPubKey, hPrvKey;					 // Хэндлы ключей

	CK_BYTE_PTR pbtCsr = NULL_PTR;						 // Указатель на буфер, содержащий подписанный запрос на сертификат
	CK_ULONG ulCsrSize = 0;								 // Размен запроса на сертификат, в байтах

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
			* 1.3 Получение адреса функции запроса структуры с указателями		  *
			*     на функции расширения стандарта PKCS#11.                        *
			**********************************************************************/
			printf(" Getting GetFunctionListExtended function");
			pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(hModule,
																				  "C_EX_GetFunctionListExtended");
			if (pfGetFunctionListEx == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.4 Получение структуры с указателями на функции стандарта PKCS#11. *
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
			* 1.5 Получение структуры с указателями на функции расширения         *
			*     стандарта PKCS#11.                                              *
			**********************************************************************/
			printf(" Getting extended function list");
			rv = pfGetFunctionListEx(&pFunctionListEx);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			/**********************************************************************
			* 1.6 Инициализировать библиотеку                                     *
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
			* 1.7 Получить количество слотов c подключенными токенами             *
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
			* 1.8 Получить список слотов c подключенными токенами                 *
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
			* 1.9 Открыть RW сессию в первом доступном слоте                      *
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
			* 1.10 Выполнить аутентификацию с правами Пользователя                *
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
		* Шаг 2: Создание запроса на сертификат                               *
		**********************************************************************/
		/**********************************************************************
		* 2.1 Cоздание ключей на токене									      *
		**********************************************************************/
		printf("\nGenerating key pair");
		rv = pFunctionList->C_GenerateKeyPair(hSession,
			                                  &ckmGOST34_10_2001KeyGenMech,
			                                  PublicKeyTmpl,
			                                  arraysize(PublicKeyTmpl),
			                                  PrivateKeyTmpl,
			                                  arraysize(PrivateKeyTmpl),
			                                  &hPubKey,
			                                  &hPrvKey);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n"
				    "Generation GOST key pairs failed!\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* 2.2 Cоздание запроса на сертификат     				              *
		**********************************************************************/
		printf("Creating certificate request");
		rv = pFunctionListEx->C_EX_CreateCSR(hSession,
											 hPubKey,
											 dn,
											 sizeof(dn) / sizeof(dn[0]),
											 &pbtCsr,
											 &ulCsrSize,
											 hPrvKey,
											 NULL,
											 0,
											 exts,
											 sizeof(exts) / sizeof(exts[0])
											);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/************************************************************************
		* 2.3 Распечатать буфер, содержащий запрос на сертификат                *
		************************************************************************/
		printf("Certficate request buffer is: \n ");
		for (i = 0;	 i < ulCsrSize;	 i++)
		{
			printf("%02X ", pbtCsr[i]);
			if ((i + 1) % 8 == 0)
				printf("\n ");
		}

		/**********************************************************************
		* 2.4 Освобождение памяти								              *
		**********************************************************************/
		printf("\nC_EX_FreeBuffer");
		rv = pFunctionListEx->C_EX_FreeBuffer(pbtCsr);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* 2.5 Удаление всех созданных объектов					              *
		**********************************************************************/
		printf("Deleting private key");
		rv = pFunctionList->C_DestroyObject(hSession, hPrvKey);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		printf("Deleting public key");
		rv = pFunctionList->C_DestroyObject(hSession, hPubKey);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");
		break;
	}

	/**********************************************************************
	* Шаг 3: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");
	rvTemp = CKR_OK;
	if (hSession)
	{
		/**********************************************************************
		* 3.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 3.2 Закрыть все открытые сессии в слоте                             *
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
		* 3.3 Деинициализировать библиотеку                                   *
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
		* 3.4 Выгрузить библиотеку из памяти                                  *
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

	if (aSlots)
	{
		free(aSlots);
		aSlots = NULL_PTR;
	}

	if ((rv != CKR_OK) || (ulSlotCount == 0))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}
