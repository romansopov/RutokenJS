/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен ЭЦП при помощи библиотеки PKCS#11 на языке C   *
*------------------------------------------------------------------------*
* Использование команды получения информации о сертификате на токене:	 *
*  - установление соединения с Рутокен ЭЦП в первом доступном слоте;     *
*  - выполнение аутентификации c правами Пользователя;					 *
*  - импорт сертификата на Рутокен;										 *
*  - получение информации об импортированном на Рутокен сертификате;	 *
*  - сравнение полученной информации о сертификате с эталонным значением;*
*  - удаление созданных объектов;										 *
*  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
*    соединения с Рутокен PINPad.                                        *
*------------------------------------------------------------------------*
* Пример самодостаточен.		                                         *
*************************************************************************/

#include "Common.h"

/************************************************************************
* Значение сертификата ключа подписи						            *
************************************************************************/
CK_BYTE cbCertificate[] = { 0x30, 0x82, 0x03, 0x36, 0x30, 0x82, 0x02, 0xe5,
							0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x24,
							0xa5, 0x24, 0x63, 0x00, 0x02, 0x00, 0x01, 0xa7,
							0x15, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03,
							0x02, 0x02, 0x03, 0x30, 0x65, 0x31, 0x20, 0x30,
							0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
							0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x69, 0x6e,
							0x66, 0x6f, 0x40, 0x63, 0x72, 0x79, 0x70, 0x74,
							0x6f, 0x70, 0x72, 0x6f, 0x2e, 0x72, 0x75, 0x31,
							0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
							0x13, 0x02, 0x52, 0x55, 0x31, 0x13, 0x30, 0x11,
							0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x43,
							0x52, 0x59, 0x50, 0x54, 0x4f, 0x2d, 0x50, 0x52,
							0x4f, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55,
							0x04, 0x03, 0x13, 0x16, 0x54, 0x65, 0x73, 0x74,
							0x20, 0x43, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x20,
							0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x2d, 0x50,
							0x52, 0x4f, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x31,
							0x31, 0x31, 0x32, 0x32, 0x31, 0x30, 0x31, 0x33,
							0x34, 0x32, 0x5a, 0x17, 0x0d, 0x31, 0x34, 0x31,
							0x30, 0x30, 0x34, 0x30, 0x37, 0x30, 0x39, 0x34,
							0x31, 0x5a, 0x30, 0x65, 0x31, 0x10, 0x30, 0x0e,
							0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x49,
							0x76, 0x61, 0x6e, 0x6f, 0x66, 0x66, 0x31, 0x0b,
							0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
							0x02, 0x52, 0x55, 0x31, 0x14, 0x30, 0x12, 0x06,
							0x03, 0x55, 0x04, 0x05, 0x13, 0x0b, 0x31, 0x32,
							0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31,
							0x32, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x09, 0x2a,
							0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
							0x16, 0x0e, 0x69, 0x76, 0x61, 0x6e, 0x6f, 0x76,
							0x40, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x72, 0x75,
							0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
							0x08, 0x13, 0x06, 0x4d, 0x6f, 0x73, 0x63, 0x6f,
							0x77, 0x30, 0x63, 0x30, 0x1c, 0x06, 0x06, 0x2a,
							0x85, 0x03, 0x02, 0x02, 0x13, 0x30, 0x12, 0x06,
							0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01,
							0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e,
							0x01, 0x03, 0x43, 0x00, 0x04, 0x40, 0xfb, 0x3c,
							0xdc, 0x59, 0xc3, 0x9c, 0x4a, 0x43, 0x89, 0x87,
							0xc7, 0xd7, 0xfe, 0x50, 0x19, 0xb3, 0x0c, 0x8b,
							0x76, 0x97, 0xa9, 0xdf, 0xb7, 0xca, 0x2c, 0x6c,
							0x3b, 0xa9, 0x13, 0xf4, 0xe0, 0x69, 0x02, 0x59,
							0x92, 0x47, 0x21, 0x1a, 0xef, 0x90, 0x61, 0x91,
							0x40, 0x30, 0xdd, 0x7c, 0xb0, 0x4f, 0x64, 0x5f,
							0x24, 0x9a, 0xf1, 0xd6, 0x0f, 0xa9, 0xf0, 0x86,
							0xd9, 0x35, 0x2b, 0x3e, 0xf2, 0xf3, 0xa3, 0x82,
							0x01, 0x73, 0x30, 0x82, 0x01, 0x6f, 0x30, 0x0b,
							0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03,
							0x02, 0x04, 0xf0, 0x30, 0x26, 0x06, 0x03, 0x55,
							0x1d, 0x25, 0x04, 0x1f, 0x30, 0x1d, 0x06, 0x07,
							0x2a, 0x85, 0x03, 0x02, 0x02, 0x22, 0x06, 0x06,
							0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
							0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
							0x07, 0x03, 0x04, 0x30, 0x1d, 0x06, 0x03, 0x55,
							0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x8a, 0x24,
							0x35, 0x74, 0x6b, 0xf7, 0x91, 0x17, 0x92, 0xb2,
							0xcf, 0x8f, 0x63, 0x87, 0xb7, 0x69, 0x06, 0xe1,
							0x71, 0xf2, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
							0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6d,
							0x8f, 0x5e, 0x05, 0xd9, 0x5f, 0xac, 0x91, 0x17,
							0x94, 0x1e, 0x95, 0x9a, 0x05, 0x30, 0x38, 0x37,
							0x7a, 0x10, 0x2a, 0x30, 0x55, 0x06, 0x03, 0x55,
							0x1d, 0x1f, 0x04, 0x4e, 0x30, 0x4c, 0x30, 0x4a,
							0xa0, 0x48, 0xa0, 0x46, 0x86, 0x44, 0x68, 0x74,
							0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
							0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x70,
							0x72, 0x6f, 0x2e, 0x72, 0x75, 0x2f, 0x43, 0x65,
							0x72, 0x74, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c,
							0x2f, 0x54, 0x65, 0x73, 0x74, 0x25, 0x32, 0x30,
							0x43, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x25, 0x32,
							0x30, 0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x2d,
							0x50, 0x52, 0x4f, 0x28, 0x32, 0x29, 0x2e, 0x63,
							0x72, 0x6c, 0x30, 0x81, 0xa0, 0x06, 0x08, 0x2b,
							0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04,
							0x81, 0x93, 0x30, 0x81, 0x90, 0x30, 0x33, 0x06,
							0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
							0x01, 0x86, 0x27, 0x68, 0x74, 0x74, 0x70, 0x3a,
							0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x63, 0x72,
							0x79, 0x70, 0x74, 0x6f, 0x70, 0x72, 0x6f, 0x2e,
							0x72, 0x75, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x6e,
							0x63, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x73,
							0x72, 0x66, 0x30, 0x59, 0x06, 0x08, 0x2b, 0x06,
							0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x4d,
							0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
							0x77, 0x77, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
							0x6f, 0x70, 0x72, 0x6f, 0x2e, 0x72, 0x75, 0x2f,
							0x43, 0x65, 0x72, 0x74, 0x45, 0x6e, 0x72, 0x6f,
							0x6c, 0x6c, 0x2f, 0x70, 0x6b, 0x69, 0x2d, 0x73,
							0x69, 0x74, 0x65, 0x5f, 0x54, 0x65, 0x73, 0x74,
							0x25, 0x32, 0x30, 0x43, 0x65, 0x6e, 0x74, 0x65,
							0x72, 0x25, 0x32, 0x30, 0x43, 0x52, 0x59, 0x50,
							0x54, 0x4f, 0x2d, 0x50, 0x52, 0x4f, 0x28, 0x32,
							0x29, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x08, 0x06,
							0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x03, 0x03,
							0x41, 0x00, 0x2b, 0xd2, 0xfe, 0x64, 0x54, 0x3a,
							0xe1, 0xf6, 0x89, 0x75, 0xfe, 0xbb, 0xa6, 0x29,
							0xed, 0x0b, 0x92, 0xc0, 0xa4, 0x84, 0x15, 0x59,
							0x23, 0x12, 0x08, 0xbb, 0xd3, 0xab, 0x8e, 0x2e,
							0x75, 0xb9, 0xbf, 0x9e, 0xd1, 0x9d, 0x1e, 0xf9,
							0x6a, 0x24, 0xed, 0xb8, 0x58, 0x15, 0x1f, 0x03,
							0x11, 0xfa, 0xd3, 0x85, 0xf1, 0x34, 0x96, 0xac,
							0x20, 0x8e, 0xdd, 0xad, 0x4e, 0xae, 0x55, 0x3e,
							0x8d, 0xd1, 0xff,
};

/************************************************************************
* Шаблон для импорта сертификата ключа подписи			                *
************************************************************************/
CK_ATTRIBUTE CertTmpl[] =
{
	{ CKA_CLASS, &ocCert, sizeof(ocCert)},							// Объект сертификата
	{ CKA_ID, &KeyPairIDGOST1, sizeof(KeyPairIDGOST1) - 1},         // Идентификатор сертификата
	{ CKA_TOKEN, &bTrue, sizeof(bTrue)},                            // Сертификат является объектом токена
	{ CKA_PRIVATE, &bFalse, sizeof(bFalse)},                        // Сертификат доступен без авторизации на токене
	{ CKA_VALUE, &cbCertificate, sizeof(cbCertificate)}				// Значение сертификата
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

	CK_OBJECT_HANDLE hCert;								 // Хэндл сертификата
	
	CK_BYTE_PTR pbtInfo = NULL_PTR;						 // Указатель на буфер, содержащий информацию о сертификате
	CK_ULONG ulInfoSize = 0;							 // Размер буфера, содержащего информацию о сертификате, в байтах

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
			rv = pFunctionList->C_OpenSession(	aSlots[0],
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
		* Шаг 2: Получение информации о сертификате                           *
		**********************************************************************/
		
		/**********************************************************************
		* 2.1 Cоздание сертификата на токене					              *
		**********************************************************************/
		printf("\nCreating certificate");
		rv = pFunctionList->C_CreateObject( hSession, 
											CertTmpl, 
											arraysize(CertTmpl),
											&hCert);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* 2.2 Получение информации о сертификате				              *
		**********************************************************************/
		printf("Getting cerificate info");
		rv = pFunctionListEx->C_EX_GetCertificateInfoText( hSession, 
														   hCert, 
														   &pbtInfo, 
														   &ulInfoSize);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/************************************************************************
		* 2.3 Распечатать буфер, содержащий информацию о сертификате            *
		************************************************************************/
		printf("Certificate info buffer is: \n ");
		for (i = 0;
			    i < ulInfoSize;
			    i++)
		{
			printf("%02X ", pbtInfo[i]);
			if ((i + 1) % 8 == 0)
				printf("\n ");
		}

		/**********************************************************************
		* 2.4 Освобождение памяти								              *
		**********************************************************************/
		printf("\nC_EX_FreeBuffer");
		rv = pFunctionListEx->C_EX_FreeBuffer(pbtInfo);
		if (rv != CKR_OK)
		{
			printf(" -> Failed\n");
			break;
		}
		printf(" -> OK\n");

		/**********************************************************************
		* 2.5 Удаление созданных объектов						              *
		**********************************************************************/
		printf("Deleting certificate");
		rv = pFunctionList->C_DestroyObject(hSession, hCert);
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
