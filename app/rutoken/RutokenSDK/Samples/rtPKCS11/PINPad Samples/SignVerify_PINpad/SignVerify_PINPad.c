/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11           *
* на языке C                                                             *
*------------------------------------------------------------------------*
* Использование команд вычисления/проверки ЭП на ключах ГОСТ 34.10-2001: *
*  - установление соединения с Рутокен PINPad в первом доступном слоте;  *
*  - выполнение аутентификации c правами Пользователя;					 *
*  - подпись отображаемых платежных данных на экране PINPad              *
*    на демонстрационном ключе;                                          *
*  - подпись запроса на сертификат для демонстрационной ключевой пары    *
*    на демонстрационном ключе;                                          *
*  - проверка подписи на демонстрационном ключе;                         *
*  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
*    соединения с Рутокен PINPad.                                        *
*------------------------------------------------------------------------*
* Пример использует объекты, созданные в памяти Рутокен PINPad примером  *
* CreateGOST34.10-2001_PINPad.                                           *
*************************************************************************/

#include "Common.h"

/* Данные для подписи в виде ANSI строки:
файл с исходным кодом должен быть сохранен в однобайтовой кодировке ANSI,
на текущей машине установлена кодировка CP-1251 для не-UNICODE программ */
char ANSIData[] = "<!PINPADFILE RU><!>невидимый текст<N>ФИО:<V>Петров Петр Петрович Москва, Пионерская ул, д. 3, кв. 72<N>Перевод со счета:<V>42301810001000075212<N>Сумма:<V>150000<N>Валюта:<V>RUR<N>Наименование получателя:<V>Иванова Елена Ивановна<N>Номер счета получателя:<V>40817810338295201618<N>БИК банка получателя:<V>044525225<N>Наименование банка получателя:<V>ОАО 'СБЕРБАНК РОССИИ' Г. МОСКВА<N>Номер счета банка получателя:<V>30101810400000000225<N>Назначение платежа:<V>перевод личных средств";

/* Формат сообщения, распознаваемого PINPad:
<!PINPADFILE RU>		// обязательный признак строки, которая будет распознаваться Rutoken PINPad
<!>some text			// текст, нераспознаваемый Rutoken PINPad
<N>some text            // наименование поля
<V>some text            // значение поля
*/

/* Данные для подписи в виде двоичной строки */
CK_BYTE pbtData[] = { 0x3C, 0x21, 0x50, 0x49, 0x4E, 0x50, 0x41, 0x44, 0x46, 0x49, 0x4C, 0x45, 0x20, 0x52, 0x55, 0x3E, 
					  0x3C, 0x21, 0x3E, 0xED, 0xE5, 0xE2, 0xE8, 0xE4, 0xE8, 0xEC, 0xFB, 0xE9, 0x20, 0xF2, 0xE5, 0xEA, 
					  0xF1, 0xF2, 0x3C, 0x4E, 0x3E, 0xD4, 0xC8, 0xCE, 0x3A, 0x3C, 0x56, 0x3E, 0xCF, 0xE5, 0xF2, 0xF0, 
					  0xEE, 0xE2, 0x20, 0xCF, 0xE5, 0xF2, 0xF0, 0x20, 0xCF, 0xE5, 0xF2, 0xF0, 0xEE, 0xE2, 0xE8, 0xF7, 
					  0x20, 0xCC, 0xEE, 0xF1, 0xEA, 0xE2, 0xE0, 0x2C, 0x20, 0xCF, 0xE8, 0xEE, 0xED, 0xE5, 0xF0, 0xF1, 
					  0xEA, 0xE0, 0xFF, 0x20, 0xF3, 0xEB, 0x2C, 0x20, 0xE4, 0x2E, 0x20, 0x33, 0x2C, 0x20, 0xEA, 0xE2,
					  0x2E, 0x20, 0x37, 0x32, 0x3C, 0x4E, 0x3E, 0xCF, 0xE5, 0xF0, 0xE5, 0xE2, 0xEE, 0xE4, 0x20, 0xF1, 
					  0xEE, 0x20, 0xF1, 0xF7, 0xE5, 0xF2, 0xE0, 0x3A, 0x3C, 0x56, 0x3E, 0x34, 0x32, 0x33, 0x30, 0x31, 
					  0x38, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x37, 0x35, 0x32, 0x31, 0x32, 0x3C, 
					  0x4E, 0x3E, 0xD1, 0xF3, 0xEC, 0xEC, 0xE0, 0x3A, 0x3C, 0x56, 0x3E, 0x31, 0x35, 0x30, 0x30, 0x30, 
					  0x30, 0x3C, 0x4E, 0x3E, 0xC2, 0xE0, 0xEB, 0xFE, 0xF2, 0xE0, 0x3A, 0x3C, 0x56, 0x3E, 0x52, 0x55, 
					  0x52, 0x3C, 0x4E, 0x3E, 0xCD, 0xE0, 0xE8, 0xEC, 0xE5, 0xED, 0xEE, 0xE2, 0xE0, 0xED, 0xE8, 0xE5, 
					  0x20, 0xEF, 0xEE, 0xEB, 0xF3, 0xF7, 0xE0, 0xF2, 0xE5, 0xEB, 0xFF, 0x3A, 0x3C, 0x56, 0x3E, 0xC8, 
					  0xE2, 0xE0, 0xED, 0xEE, 0xE2, 0xE0, 0x20, 0xC5, 0xEB, 0xE5, 0xED, 0xE0, 0x20, 0xC8, 0xE2, 0xE0, 
					  0xED, 0xEE, 0xE2, 0xED, 0xE0, 0x3C, 0x4E, 0x3E, 0xCD, 0xEE, 0xEC, 0xE5, 0xF0, 0x20, 0xF1, 0xF7, 
					  0xE5, 0xF2, 0xE0, 0x20, 0xEF, 0xEE, 0xEB, 0xF3, 0xF7, 0xE0, 0xF2, 0xE5, 0xEB, 0xFF, 0x3A, 0x3C, 
					  0x56, 0x3E, 0x34, 0x30, 0x38, 0x31, 0x37, 0x38, 0x31, 0x30, 0x33, 0x33, 0x38, 0x32, 0x39, 0x35, 
					  0x32, 0x30, 0x31, 0x36, 0x31, 0x38, 0x3C, 0x4E, 0x3E, 0xC1, 0xC8, 0xCA, 0x20, 0xE1, 0xE0, 0xED, 
					  0xEA, 0xE0, 0x20, 0xEF, 0xEE, 0xEB, 0xF3, 0xF7, 0xE0, 0xF2, 0xE5, 0xEB, 0xFF, 0x3A, 0x3C, 0x56, 
					  0x3E, 0x30, 0x34, 0x34, 0x35, 0x32, 0x35, 0x32, 0x32, 0x35, 0x3C, 0x4E, 0x3E, 0xCD, 0xE0, 0xE8, 
					  0xEC, 0xE5, 0xED, 0xEE, 0xE2, 0xE0, 0xED, 0xE8, 0xE5, 0x20, 0xE1, 0xE0, 0xED, 0xEA, 0xE0, 0x20, 
					  0xEF, 0xEE, 0xEB, 0xF3, 0xF7, 0xE0, 0xF2, 0xE5, 0xEB, 0xFF, 0x3A, 0x3C, 0x56, 0x3E, 0xCE, 0xC0, 
					  0xCE, 0x20, 0x27, 0xD1, 0xC1, 0xC5, 0xD0, 0xC1, 0xC0, 0xCD, 0xCA, 0x20, 0xD0, 0xCE, 0xD1, 0xD1, 
					  0xC8, 0xC8, 0x27, 0x20, 0xC3, 0x2E, 0x20, 0xCC, 0xCE, 0xD1, 0xCA, 0xC2, 0xC0, 0x3C, 0x4E, 0x3E, 
					  0xCD, 0xEE, 0xEC, 0xE5, 0xF0, 0x20, 0xF1, 0xF7, 0xE5, 0xF2, 0xE0, 0x20, 0xE1, 0xE0, 0xED, 0xEA, 
					  0xE0, 0x20, 0xEF, 0xEE, 0xEB, 0xF3, 0xF7, 0xE0, 0xF2, 0xE5, 0xEB, 0xFF, 0x3A, 0x3C, 0x56, 0x3E, 
					  0x33, 0x30, 0x31, 0x30, 0x31, 0x38, 0x31, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 
					  0x30, 0x32, 0x32, 0x35, 0x3C, 0x4E, 0x3E, 0xCD, 0xE0, 0xE7, 0xED, 0xE0, 0xF7, 0xE5, 0xED, 0xE8, 
					  0xE5, 0x20, 0xEF, 0xEB, 0xE0, 0xF2, 0xE5, 0xE6, 0xE0, 0x3A, 0x3C, 0x56, 0x3E, 0xEF, 0xE5, 0xF0, 
					  0xE5, 0xE2, 0xEE, 0xE4, 0x20, 0xEB, 0xE8, 0xF7, 0xED, 0xFB, 0xF5, 0x20, 0xF1, 0xF0, 0xE5, 0xE4, 
					  0xF1, 0xF2, 0xE2 };

CK_BYTE pbtReqCert[] = {0x30, 0x82, 0x02, 0x69, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x83, 0x31, 0x0b, 0x30, 0x09, 0x06,
						0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
						0x08, 0x13, 0x06, 0x4d, 0x6f, 0x73, 0x63, 0x6f, 0x77, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
						0x04, 0x07, 0x13, 0x03, 0x6d, 0x73, 0x6b, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x09,
						0x13, 0x06, 0x73, 0x74, 0x72, 0x65, 0x65, 0x74, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
						0x0a, 0x13, 0x05, 0x41, 0x6b, 0x74, 0x69, 0x76, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
						0x0b, 0x13, 0x02, 0x49, 0x54, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x10, 0x13, 0x0e,
						0x70, 0x6f, 0x73, 0x74, 0x61, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x31, 0x1b,
						0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0c, 0x1e, 0x12, 0x04, 0x34, 0x04, 0x3e, 0x04, 0x3b, 0x04,
						0x36, 0x04, 0x3d, 0x04, 0x3e, 0x04, 0x41, 0x04, 0x42, 0x04, 0x4c, 0x31, 0x19, 0x30, 0x17, 0x06,
						0x08, 0x2a, 0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35,
						0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64,
						0x03, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16,
						0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64, 0x01, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35,
						0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x16, 0x30, 0x14, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64,
						0x05, 0x12, 0x0b, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x38, 0x37, 0x31, 0x2f,
						0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x26, 0x04, 0x24, 0x04, 0x30, 0x04, 0x3c, 0x04,
						0x38, 0x04, 0x3b, 0x04, 0x38, 0x04, 0x4f, 0x00, 0x20, 0x04, 0x18, 0x04, 0x3c, 0x04, 0x4f, 0x00,
						0x20, 0x04, 0x1e, 0x04, 0x47, 0x04, 0x35, 0x04, 0x41, 0x04, 0x42, 0x04, 0x32, 0x04, 0x3e, 0x31,
						0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x41, 0x13, 0x09, 0x70, 0x73, 0x65, 0x75, 0x64, 0x6f,
						0x6e, 0x79, 0x6d, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x13, 0x07, 0x73, 0x75,
						0x72, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x13, 0x0a,
						0x67, 0x69, 0x76, 0x65, 0x6e, 0x20, 0x6e, 0x61,	0x6d, 0x65, 0x31, 0x22, 0x30, 0x20, 0x06, 0x09,
						0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,	0x01, 0x16, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
						0x6c, 0x65, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70,	0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x63,
						0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02,	0x02, 0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85,
						0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 0x2a,	0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x03, 0x43,
						0x00, 0x04, 0x40, 0x26, 0x68, 0x22, 0x87, 0x6b,	0x3e, 0x60, 0xde, 0x6e, 0xcf, 0x7d, 0x9b, 0xc5,
						0x99, 0x49, 0x88, 0xe3, 0xce, 0x8d, 0x05, 0xb2,	0x0a, 0x3c, 0x3d, 0x2c, 0xb3, 0x7c, 0xc6, 0x9e,
						0x7e, 0x5a, 0xc6, 0x95, 0xde, 0x97, 0x86, 0x9a,	0x56, 0xe3, 0xc5, 0xf5, 0xc5, 0xca, 0x9a, 0x4a,
						0xd9, 0x11, 0xa0, 0x40, 0x08, 0xca, 0x70, 0x29,	0x13, 0x64, 0x7f, 0xa1, 0x6c, 0x5b, 0x5b, 0x25,
						0xc9, 0xa6, 0x0c, 0xa0, 0x78, 0x30, 0x76, 0x06,	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
						0x09, 0x0e, 0x31, 0x69, 0x30, 0x67, 0x30, 0x0b,	0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03,
						0x02, 0x06, 0xc0, 0x30, 0x16, 0x06, 0x03, 0x55,	0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30,
						0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,	0x07, 0x03, 0x04, 0x30, 0x13, 0x06, 0x03, 0x55,
						0x1d, 0x20, 0x04, 0x0c, 0x30, 0x0a, 0x30, 0x08,	0x06, 0x06, 0x2a, 0x85, 0x03, 0x64, 0x71, 0x01,
						0x30, 0x2b, 0x06, 0x05, 0x2a, 0x85, 0x03, 0x64,	0x6f, 0x04, 0x22, 0x0c, 0x20, 0xd0, 0xa1, 0xd0,
						0x9a, 0xd0, 0x97, 0xd0, 0x98, 0x20, 0x22, 0xd0,	0xa0, 0xd0, 0xa3, 0xd0, 0xa2, 0xd0, 0x9e, 0xd0,
						0x9a, 0xd0, 0x95, 0xd0, 0x9d, 0x20, 0xd0, 0xad, 0xd0, 0xa6, 0xd0, 0x9f, 0x22
};

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
BOOL FindObjects(IN CK_SESSION_HANDLE hSession,  // Хэндл открытой сессии
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
BOOL HashData(IN CK_SESSION_HANDLE hSession,      // Хэндл открытой сессии
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
	
	CK_ATTRIBUTE attrPublicValue = { CKA_VALUE, NULL_PTR, 0 }; // Шаблон для получения атрибутов открытого ключа

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
		* Шаг 2: Выполнить подпись платежной информации по алгоритму		  *
		*        ГОСТ Р 34.10-2001.                                           *
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

		/**********************************************************************
		* Шаг 4: Выполнить подпись запроса на сертификат по алгоритму         *
		* ГОСТ Р 34.10-2001.                                                  *
		**********************************************************************/

		printf("\nSigning certificate request...\n");
		while (TRUE)
		{
						
			/************************************************************************
			* 4.1 Получить массив хэндлов открытых ключей                           *
			************************************************************************/
			printf(" Getting public key...\n");
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
				printf("\nNo public key found!\n");
				break;
			}

			/**********************************************************************
			* 4.2 Получить значение открытого ключа                               *
			**********************************************************************/
			printf(" Getting public key value");

			rv = pFunctionList->C_GetAttributeValue(hSession,
								phObject[0],
								&attrPublicValue,
								1);
			if (rv != CKR_OK)
			{
				printf(" -> Failed\n");
				break;
			}
			printf(" -> OK\n");

			attrPublicValue.pValue = (CK_BYTE*)malloc(attrPublicValue.ulValueLen);
			memset(attrPublicValue.pValue,
				0,
				(attrPublicValue.ulValueLen * sizeof(CK_BYTE)));

			rv = pFunctionList->C_GetAttributeValue(hSession,
				phObject[0],
				&attrPublicValue,
				1);

			printf(" Public key:\n");
			for (i = 0; i < attrPublicValue.ulValueLen; i++)
			{
				printf(" %02X", ((CK_BYTE_PTR)attrPublicValue.pValue)[i]);
				if ((i + 1) % 8 == 0)
					printf("\n");
			}

			/**********************************************************************
			* 4.3 Внести значение открытого ключа в запрос на сертификат          *
			**********************************************************************/
			for (i = 0; i < 64; i++)
				pbtReqCert[i + 435] = (((CK_BYTE_PTR)attrPublicValue.pValue)[i]);
			
			/************************************************************************
			* 4.4 Получить массив хэндлов закрытых ключей                           *
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
			* 4.5 Сформировать хеш от исходных данных                             *
			**********************************************************************/
			HashData(hSession,
					pFunctionList,
					&ckmGOST34_11_94Mech,
					pbtReqCert,
					arraysize(pbtReqCert),
					&pbHash,
					&ulHashSize,
					&rv);

			if (rv != CKR_OK)
				break;
			
			/**********************************************************************
			* 4.6 Инициализировать операцию подписи данных                        *
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
			* 4.7 Определить размер зашифрованных данных                          *
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
			* 4.8 Подписать исходные данные                                       *
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
			* 4.9 Распечатать буфер, содержащий подпись                             *
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
		* Шаг 5: Выполнить проверку подписи данных                            *
		*        по алгоритму ГОСТ Р 34.10-2001.                              *
		**********************************************************************/
		printf("\nVerifying signature...\n");
		while (TRUE)
		{
			/************************************************************************
			* 5.1 Получить массив хэндлов открытых ключей                           *
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
			* 5.2 Сформировать хеш от исходных данных                             *
			**********************************************************************/
			HashData(hSession,
			         pFunctionList,
			         &ckmGOST34_11_94Mech,
			         pbtReqCert,
					 arraysize(pbtReqCert),
			         &pbHash,
			         &ulHashSize,
			         &rv);


			if (rv != CKR_OK)
				break;

			/**********************************************************************
			* 5.3 Инициализировать операцию проверки подписи                      *
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
			* 5.4 Проверить подпись для исходных данных                           *
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
	* Шаг 6: Выполнить действия для завершения работы                     *
	*        с библиотекой PKCS#11.                                       *
	**********************************************************************/
	printf("\nFinalizing... \n");
	rvTemp = CKR_OK;
	if (hSession)
	{
		/**********************************************************************
		* 6.1 Сбросить права доступа                                          *
		**********************************************************************/
		printf(" Logging out");
		rvTemp = pFunctionList->C_Logout(hSession);
		if ((rvTemp == CKR_OK) || (rvTemp == CKR_USER_NOT_LOGGED_IN))
			printf(" -> OK\n");
		else
			printf(" -> Failed\n");

		/**********************************************************************
		* 6.2 Закрыть все открытые сессии в слоте                             *
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
		* 6.3 Деинициализировать библиотеку                                   *
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
		* 6.4 Выгрузить библиотеку из памяти                                  *
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
