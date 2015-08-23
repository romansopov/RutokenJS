/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд создания различных объектов в памяти Рутокен:     *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - создание ключевой пары RSA;                                         *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Данный пример является одним из серии примеров работы с библиотекой    *
* PKCS#11. Созданные примером объекты используются также и в других      *
* примерах работы с библиотекой PKCS#11.                                 *
*************************************************************************/

#include "Common.h"

/************************************************************************
* Шаблон для создания открытого ключа RSA                               *
* (ключевая пара для подписи и шифрования)                              *
************************************************************************/
CK_ATTRIBUTE attrRSAExchPublicKeyTmpl[] =
{
	{ CKA_CLASS, &ocPubKey, sizeof(ocPubKey)},                      // Объект открытого ключа RSA
	{ CKA_LABEL, &PubLabelRSA, sizeof(PubLabelRSA) - 1},            // Метка ключа
	{ CKA_ID, &KeyPairIDRSA, sizeof(KeyPairIDRSA) - 1},             // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktRSA, sizeof(ktRSA)},                         // Тип ключа
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_ENCRYPT, &bTrue, sizeof(bTrue)},                          // Ключ предназначен для зашифрования
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Ключ доступен без авторизации на токене
	{ CKA_MODULUS_BITS, &ulRSAModBits, sizeof(ulRSAModBits)}        // Длина модуля ключа
};

/************************************************************************
* Шаблон для создания закрытого ключа RSA                               *
* (Ключевая пара для подписи и шифрования)                              *
************************************************************************/
CK_ATTRIBUTE attrRSAExchPrivateKeyTmpl[] =
{
	{ CKA_CLASS, &ocPrivKey, sizeof(ocPrivKey)},                // Объект закрытого ключа RSA
	{ CKA_LABEL, &PrivLabelRSA, sizeof(PrivLabelRSA) - 1},      // Метка ключа
	{ CKA_ID, &KeyPairIDRSA, sizeof(KeyPairIDRSA) - 1},         // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
	{ CKA_KEY_TYPE, &ktRSA, sizeof(ktRSA)},                     // Тип ключа
	{ CKA_DECRYPT, &bTrue, sizeof(bTrue)},                      // Ключ предназначен для расшифрования
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                        // Ключ является объектом токена
	{ CKA_PRIVATE, &bTrue, sizeof(bTrue)}                       // Ключ доступен только после авторизации на токене
};

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                          // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;               // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;       // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;   // Указатель на функцию C_GetFunctionList

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                    // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                            // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE hRSAExchPublicKey = NULL_PTR;       // Хэндл открытого ключа RSA (ключевая пара для подписи и шифрования)
	CK_OBJECT_HANDLE hRSAExchPrivateKey = NULL_PTR;      // Хэндл закрытого ключа RSA (ключевая пара для подписи и шифрования)

	CK_RV rv = CKR_OK;                                   // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                               // Вспомогательная переменная для хранения кода возврата

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
			printf(" Loading library %s", PKCS11_LIBRARY_NAME); // или PKCS11ECP_LIBRARY_NAME
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

		/**********************************************************************
		* Шаг 2: Сгенерировать ключевую пару RSA.                             *
		**********************************************************************/
		printf("\nGenerating RSA exchange key pair...\n");
		printf(" C_GenerateKeyPair");
		rv = pFunctionList->C_GenerateKeyPair(hSession,                                 // Хэндл открытой сессии
		                                      &ckmRSAKeyGenMech,                        // Используемый механизм генерации ключей RSA
		                                      attrRSAExchPublicKeyTmpl,                 // Шаблон для создания открытого ключа RSA
		                                      arraysize(attrRSAExchPublicKeyTmpl),      // Размер шаблона открытого ключа
		                                      attrRSAExchPrivateKeyTmpl,                // Шаблон для создания закрытого ключа RSA
		                                      arraysize(attrRSAExchPrivateKeyTmpl),     // Размер шаблона закрытого ключа
		                                      &hRSAExchPublicKey,                       // Хэндл открытого ключа RSA
		                                      &hRSAExchPrivateKey);                     // Хэндл закрытого ключа RSA
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n"
			       "Generation RSA key pair failed!\n");
			break;
		}
		printf(" -> OK\n"
		       "Generation RSA key pair has been completed successfully.\n");
		break;
	}

	/**********************************************************************
	* Шаг 3: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");

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

