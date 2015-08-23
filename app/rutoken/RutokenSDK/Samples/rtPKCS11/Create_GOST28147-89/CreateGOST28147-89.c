/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд создания объектов в памяти Рутокен:               *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - определение типа подключенного токена;                              *
*  - выполнение аутентификации c правами Пользователя;                   *
*  - создание cимметричного ключа ГОСТ 28147-89;                         *
*  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
*    с Рутокен.                                                          *
*------------------------------------------------------------------------*
* Данный пример является одним из серии примеров работы с библиотекой    *
* PKCS#11. Созданные примером объекты используются также и в других      *
* примерах работы с библиотекой PKCS#11.                                 *
*************************************************************************/

#include "Common.h"

/************************************************************************
* Шаблон для создания симметричного ключа ГОСТ 28147-89                 *
************************************************************************/
CK_ATTRIBUTE attrGOST28147_89SecKeyTmpl[] =
{
	{ CKA_CLASS, &ocSeckey, sizeof(ocSeckey)},                      // Объект секретного ключа ГОСТ 28147-89
	{ CKA_LABEL, &SecLabelGOST, sizeof(SecLabelGOST) - 1},          // Метка ключа
	{ CKA_ID, &SecKeyIDGOST, sizeof(SecKeyIDGOST) - 1},             // Идентификатор ключа
	{ CKA_KEY_TYPE, &ktGOST28147_89, sizeof(ktGOST28147_89)},       // Тип ключа
	{ CKA_ENCRYPT, &bTrue, sizeof(bTrue)},                          // Ключ предназначен для зашифрования
	{ CKA_DECRYPT, &bTrue, sizeof(bTrue)},                          // Ключ предназначен для расшифрования
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Ключ является объектом токена
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Ключ доступен без авторизации на токене
	{ CKA_GOST28147_PARAMS, GOST28147_params_oid, sizeof(GOST28147_params_oid)} // Параметры алгоритма из стандарта
};

/************************************************************************
* main()                                                                *
************************************************************************/
int main(int argc, char* argv[])
{
	HMODULE hModule = NULL_PTR;                                     // Хэндл загруженной библиотеки PKCS#11
	CK_SESSION_HANDLE hSession = NULL_PTR;                          // Хэндл открытой сессии

	CK_FUNCTION_LIST_PTR pFunctionList = NULL_PTR;                  // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList pfGetFunctionList = NULL_PTR;              // Указатель на функцию C_GetFunctionList

	CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = NULL_PTR; // Указатель на функцию C_EX_GetFunctionListExtended
	CK_FUNCTION_LIST_EXTENDED_PTR pFunctionListEx = NULL_PTR;       // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
	CK_TOKEN_INFO_EXTENDED tokenInfoEx;                             // Структура данных типа CK_TOKEN_INFO_EXTENDED с информацией о токене

	CK_SLOT_ID_PTR aSlots = NULL_PTR;                               // Указатель на массив идентификаторов слотов
	CK_ULONG ulSlotCount = 0;                                       // Количество идентификаторов слотов в массиве

	CK_OBJECT_HANDLE hGOST28147_89SecKey = NULL_PTR;                // Хэндл открытого ключа ГОСТ Р 34.10-2001 (первая ключевая пара для подписи и шифрования)

	CK_BBOOL bIsRutokenECP = FALSE;                                 // Вспомогательная переменная для хранения признака типа токена
	CK_RV rv = CKR_OK;                                              // Вспомогательная переменная для хранения кода возврата
	CK_RV rvTemp = CKR_OK;                                          // Вспомогательная переменная для хранения кода возврата

	while (TRUE)
	{
		/**********************************************************************
		* Шаг 1: Выполнить действия для начала работы с библиотекой PKCS#11.  *
		**********************************************************************/
		printf("Initialization module...\n");
		while (TRUE)
		{
			/**********************************************************************
			* 1.1 Загрузить библиотеку                                            *
			**********************************************************************/
			printf("Loading library %s", PKCS11ECP_LIBRARY_NAME);
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
			* 1.7 Определить класс токена                                         *
			**********************************************************************/
			printf(" Determining token type");

			/************************************************************************
			* Получить адрес функции запроса структуры с указателями на функции     *
			* расширения                                                            *
			************************************************************************/
			pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(hModule,
			                                                                      "C_EX_GetFunctionListExtended");
			if (pfGetFunctionListEx == NULL_PTR)
			{
				printf(" -> Failed\n");
				break;
			}

			/**********************************************************************
			* Получить структуру с указателями на функции расширения              *
			**********************************************************************/
			rv = pfGetFunctionListEx(&pFunctionListEx);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}

			memset(&tokenInfoEx,
			       0,
			       sizeof(CK_TOKEN_INFO_EXTENDED));
			tokenInfoEx.ulSizeofThisStructure = sizeof(CK_TOKEN_INFO_EXTENDED);

			/**********************************************************************
			* Получить расширенную информацию о подключенном токене               *
			**********************************************************************/
			rv = pFunctionListEx->C_EX_GetTokenInfoExtended(aSlots[0],
			                                                &tokenInfoEx);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}

			/**********************************************************************
			* Определить класс токена                                             *
			**********************************************************************/
			if (tokenInfoEx.ulTokenClass == TOKEN_CLASS_ECP)
			{
				bIsRutokenECP = TRUE;
				printf(": Rutoken ECP\n");
			}
			else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN_LITE)
			{
				bIsRutokenECP = FALSE;
				printf(": Rutoken Lite\n");
			}
			else if (tokenInfoEx.ulTokenType == TOKEN_TYPE_RUTOKEN)
			{
				bIsRutokenECP = FALSE;
				printf(": Rutoken / Rutoken S\n");
			}
			else
			{
				bIsRutokenECP = FALSE;
				printf(": undefined\n");
			}

			/**********************************************************************
			* 1.8 Открыть RW сессию в первом доступном слоте                      *
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
			* 1.9 Выполнить аутентификацию Пользователя                           *
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
		* Шаг 2: Сгенерировать секретный ключ ГОСТ 28147-89                   *
		**********************************************************************/
		printf("\nGenerating GOST 28147-89 secret key");

		if (bIsRutokenECP)
		{
			rv = pFunctionList->C_GenerateKey(hSession,                                 // Хэндл открытой сессии
			                                  &ckmGOST28147_89_KeyGenMech,              // Используемый механизм генерации ключа
			                                  attrGOST28147_89SecKeyTmpl,               // Шаблон для создания секретного ключа
			                                  arraysize(attrGOST28147_89SecKeyTmpl),    // Размер шаблона секретного ключа
			                                  &hGOST28147_89SecKey);                    // Хэндл секретного ключа
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n"
				       "Generation GOST key failed!\n");
				break;
			}
			printf(" -> OK\n");
		}
		else
			printf(" -> Failed. \nNo Rutoken ECP is available!\n");
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

	if ((rv != CKR_OK) || (ulSlotCount == 0) || (!bIsRutokenECP))
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rv);
	else if (rvTemp != CKR_OK)
		printf("Some error occurred. Error code: 0x%8.8x. Press Enter to exit.\n", (int)rvTemp);
	else
		printf("Test has been completed successfully. Press Enter to exit.\n");

	getchar();
	return rv != CKR_OK;
}

