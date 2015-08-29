#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <Common.h>
#include <string>

using namespace v8;

bool              bInitialize = false; // Флаг инициализации библиотеки PKCS#11 fnInitialize()

HMODULE           hModule  = NULL_PTR; // Хэндл загруженной библиотеки PKCS#11
CK_SESSION_HANDLE hSession = NULL_PTR; // Хэндл открытой сессии

CK_FUNCTION_LIST_PTR pFunctionList     = NULL_PTR; // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST

CK_SLOT_INFO      slotInfo;  // Структура данных типа CK_SLOT_INFO с информацией о слоте
CK_TOKEN_INFO     tokenInfo; // Структура данных типа CK_TOKEN_INFO с информацией о токене
CK_MECHANISM_INFO mechInfo;  // Структура данных типа CK_MECHANISM_INFO с информацией о механизме

CK_SLOT_ID_PTR aSlots      = NULL_PTR; // Указатель на массив идентификаторов всех доступных слотов
CK_ULONG       ulSlotCount = 0;        // Количество идентификаторов всех доступных слотов в массиве

CK_MECHANISM_TYPE_PTR aMechanisms      = NULL_PTR; // Указатель на массив механизмов, поддерживаемых слотом
CK_ULONG              ulMechanismCount = 0;        // Количество идентификаторов механизмов в массиве

DWORD i      = 0;      // Вспомогательная переменная-счетчик для циклов
CK_RV rv     = CKR_OK; // Вспомогательная переменная для хранения кода возврата
CK_RV rvTemp = CKR_OK; // Вспомогательная переменная для хранения кода возврата

Local<String> _S(Isolate* isolate, std::string value) {
    return String::NewFromUtf8(isolate, value.c_str());
}
Local<Integer> _I(Isolate* isolate, int value) {
    return Integer::New(isolate, value);
}

//
// Инициализация библиотеки rtPKCS11ECP.dll
//
void fnInitialize(const FunctionCallbackInfo<Value>& args) {

	if (!bInitialize)
	{
		rv = CKR_FUNCTION_FAILED;

		// Шаг 1: Загрузить библиотеку.
		hModule = LoadLibrary("rutoken/libs/windows/x64/rtPKCS11ECP.dll");

		// Шаг 2: Получить адрес функции запроса структуры с указателями на функции.
		if (hModule != NULL_PTR) {
			CK_C_GetFunctionList pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList"); // Указатель на функцию C_GetFunctionList

			// Шаг 3: Получить структуру с указателями на функции.
			if (pfGetFunctionList != NULL_PTR) {
				rv = pfGetFunctionList(&pFunctionList);

				// Шаг 4: Инициализировать библиотеку.
				if (rv == CKR_OK) {
					rv = pFunctionList->C_Initialize(NULL_PTR);

					// Шаг 5: Установить флаг isDLL = true.
					if (rv == CKR_OK) {
						bInitialize = true;
					}
					args.GetReturnValue().Set((int)rv);
				}
				else
					args.GetReturnValue().Set(-3);
			}
			else
				args.GetReturnValue().Set(-2);
		}
		else
			args.GetReturnValue().Set(-1);

		return;
	}

    args.GetReturnValue().Set(0);
}

void isInitialize(const FunctionCallbackInfo<Value>& args) {
    args.GetReturnValue().Set(bInitialize);
}

void fnFinalize(const FunctionCallbackInfo<Value>& args) {

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = pFunctionList->C_Finalize(NULL_PTR);

		if (rv == CKR_OK) {
			bInitialize = false;
		}
	}

	args.GetReturnValue().Set(!bInitialize);
}

//
// Количество зарегистрированных слотов (подключенных токенов) в системе
// Используется функция: C_GetSlotList
//
void fnCountSlot(const FunctionCallbackInfo<Value>& args) {
    int err = 0;
    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
    if (rv == CKR_OK) {
        aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
		memset(aSlots, 0, (ulSlotCount * sizeof(CK_SLOT_ID)));
        rv = pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulSlotCount);
        if (rv == CKR_OK) {
            args.GetReturnValue().Set((int)ulSlotCount);
        } else {
            err = (int)rv * -1;
        }
    } else {
        err = (int)rv * -1;
    }

    if(err != 0) {
        args.GetReturnValue().Set(err);
    }

}

//
// Получить информацию из слота
// Используется функция: C_GetSlotInfo
//
void fnGetSlotInfo(const FunctionCallbackInfo<Value>& args) {

    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int slot = aSlots[(int)args[0]->NumberValue()];

    // Callback
    Local<Function> cb   = Local<Function>::Cast(args[1]);

    Local<Object>   obj   = Object::New(isolate);
    Local<Object>   objHV = Object::New(isolate);
    Local<Object>   objFV = Object::New(isolate);

    rv = pFunctionList->C_GetSlotInfo(slot, &slotInfo);

    if (rv == CKR_OK) {
        std::string str;

        // Slot description
        str = (const char *)slotInfo.slotDescription;
        obj->Set(_S(isolate, "description"), _S(isolate, str.substr(0, (int)sizeof(slotInfo.slotDescription))));

        // Manufacturer
        str = (const char *)slotInfo.manufacturerID;
        obj->Set(_S(isolate, "manufacturerID"), _S(isolate, str.substr(0, (int)sizeof(slotInfo.manufacturerID))));

        // Flags
        obj->Set(_S(isolate, "flags"), _I(isolate, (int)slotInfo.flags));

        // Hardware Version
        objHV->Set(_S(isolate, "major"), _I(isolate, (int)slotInfo.hardwareVersion.major));
        objHV->Set(_S(isolate, "minor"), _I(isolate, (int)slotInfo.hardwareVersion.minor));
        obj->Set(_S(isolate, "hardwareVersion"), objHV);

        // Firmware Version
        objFV->Set(_S(isolate, "major"), _I(isolate, (int)slotInfo.firmwareVersion.major));
        objFV->Set(_S(isolate, "minor"), _I(isolate, (int)slotInfo.firmwareVersion.minor));
        obj->Set(_S(isolate, "firmwareVersion"), objFV);

        Local<Value> argv[1] = { obj };
        cb->Call(isolate->GetCurrentContext()->Global(), 1, argv);

        args.GetReturnValue().Set(obj);

    } else {
        args.GetReturnValue().Set((int)rv * -1);
    }

}

//
// Получить информацию из токена
// Используется функция: C_GetTokenInfo
//
void fnGetTokenInfo(const FunctionCallbackInfo<Value>& args) {

    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int slot = aSlots[(int)args[0]->NumberValue()];

    // Callback
    Local<Function> cb   = Local<Function>::Cast(args[1]);

    Local<Object>   obj   = Object::New(isolate);
    Local<Object>   objHV = Object::New(isolate);
    Local<Object>   objFV = Object::New(isolate);

    memset(&tokenInfo, 0, sizeof(CK_TOKEN_INFO));
    rv = pFunctionList->C_GetTokenInfo(slot, &tokenInfo);

    if (rv == CKR_OK) {
        std::string str;

        // Token label
        str = (const char *)tokenInfo.label;
        obj->Set(_S(isolate, "label"), _S(isolate, str.substr(0, (int)sizeof(tokenInfo.label))));

        // Manufacturer
        str = (const char *)tokenInfo.manufacturerID;
        obj->Set(_S(isolate, "manufacturerID"), _S(isolate, str.substr(0, (int)sizeof(tokenInfo.manufacturerID))));

        // Token model
        str = (const char *)tokenInfo.model;
        obj->Set(_S(isolate, "model"), _S(isolate, str.substr(0, (int)sizeof(tokenInfo.model))));

        // Token serial number
        str = (const char *)tokenInfo.serialNumber;
        obj->Set(_S(isolate, "serialNumber"), _S(isolate, str.substr(0, (int)sizeof(tokenInfo.serialNumber))));

        // Flags
        obj->Set(_S(isolate, "flags"), _I(isolate, (int)tokenInfo.flags));

        // Max session count
        obj->Set(_S(isolate, "maxSessionCount"), _I(isolate, (int)tokenInfo.ulMaxSessionCount));

        // Current session count
        obj->Set(_S(isolate, "sessionCount"), _I(isolate, (int)tokenInfo.ulSessionCount));

        // Max RW session count
        obj->Set(_S(isolate, "maxRwSessionCount"), _I(isolate, (int)tokenInfo.ulMaxRwSessionCount));

        // Current RW session count
        obj->Set(_S(isolate, "rwSessionCount"), _I(isolate, (int)tokenInfo.ulRwSessionCount));

        // Max PIN length
        obj->Set(_S(isolate, "maxPinLen"), _I(isolate, (int)tokenInfo.ulMaxPinLen));

        // Min PIN length
        obj->Set(_S(isolate, "minPinLen"), _I(isolate, (int)tokenInfo.ulMinPinLen));

        // Total public memory
        obj->Set(_S(isolate, "totalPublicMemory"), _I(isolate, (int)tokenInfo.ulTotalPublicMemory));

        // Free public memory
        obj->Set(_S(isolate, "freePublicMemory"), _I(isolate, (int)tokenInfo.ulFreePublicMemory));

        // Total private memory
        obj->Set(_S(isolate, "totalPrivateMemory"), _I(isolate, (int)tokenInfo.ulTotalPrivateMemory));

        // Free private memory
        obj->Set(_S(isolate, "freePrivateMemory"), _I(isolate, (int)tokenInfo.ulFreePrivateMemory));

        // Hardware version
        objHV->Set(_S(isolate, "major"), _I(isolate, (int)tokenInfo.hardwareVersion.major));
        objHV->Set(_S(isolate, "minor"), _I(isolate, (int)tokenInfo.hardwareVersion.minor));
        obj->Set(_S(isolate, "hardwareVersion"), objHV);

        // Firmware version
        objFV->Set(_S(isolate, "major"), _I(isolate, (int)tokenInfo.firmwareVersion.major));
        objFV->Set(_S(isolate, "minor"), _I(isolate, (int)tokenInfo.firmwareVersion.minor));
        obj->Set(_S(isolate, "firmwareVersion"), objFV);

        // Timer #
        str = (const char *)tokenInfo.utcTime;
        obj->Set(_S(isolate, "utcTime"), _S(isolate, str.substr(0, (int)sizeof(tokenInfo.utcTime))));

        Local<Value> argv[1] = { obj };
        cb->Call(isolate->GetCurrentContext()->Global(), 1, argv);

        args.GetReturnValue().Set(obj);
    } else {
        args.GetReturnValue().Set((int)rv * -1);
    }

}

//
// Получить список доступных механизмов токена
// Используется функция: C_GetMechanismList
//
void fnGetMechanismList(const FunctionCallbackInfo<Value>& args) {

    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int slot = aSlots[(int)args[0]->NumberValue()];

    // Callback
    Local<Function> cb = Local<Function>::Cast(args[1]);

    Local<Object> obj = Object::New(isolate);

    ulMechanismCount = 0;
    rv = pFunctionList->C_GetMechanismList(slot, NULL_PTR, &ulMechanismCount);

    if(rv == CKR_OK) {
        aMechanisms = (CK_MECHANISM_TYPE*)malloc(sizeof(CK_MECHANISM_TYPE) * ulMechanismCount);
        memset(aMechanisms, 0, (sizeof(CK_MECHANISM_TYPE) * ulMechanismCount));
        rv = pFunctionList->C_GetMechanismList(slot, aMechanisms, &ulMechanismCount);
        if(rv == CKR_OK) {
            Local<Array>  arr  = Array::New(isolate);

            obj->Set(_S(isolate, "count"), _I(isolate, (int)ulMechanismCount));
            obj->Set(_S(isolate, "list"), arr);

            for (i = 0; i < ulMechanismCount; i++) {
				memset(&mechInfo, 0, sizeof(CK_MECHANISM_INFO));
				rv = pFunctionList->C_GetMechanismInfo(slot, aMechanisms[i], &mechInfo);
				if (rv == CKR_OK) {
                    Local<Object> objM = Object::New(isolate);
                    objM->Set(_S(isolate, "type"),       _I(isolate, (int)aMechanisms[i]));
                    objM->Set(_S(isolate, "minKeySize"), _I(isolate, (int)mechInfo.ulMinKeySize));
                    objM->Set(_S(isolate, "maxKeySize"), _I(isolate, (int)mechInfo.ulMaxKeySize));
                    objM->Set(_S(isolate, "flags"),      _I(isolate, (int)mechInfo.flags));
                    arr->Set(i, objM);
				} else {
                    break;
                }
            }

            Local<Value> argv[1] = { obj };
            cb->Call(isolate->GetCurrentContext()->Global(), 1, argv);

            args.GetReturnValue().Set(obj);
        } else {
            // TODO

        }
    } else {
        // TODO

    }

}

//
// Функция открывает сессию и авторизует пользователя на токене.
//
void fnLogin(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    int slot = aSlots[(int)args[0]->NumberValue()];

    // PIN
    String::Utf8Value arg1(args[1]->ToString());
    std::string pin = std::string(*arg1);

    // Открываем сессию
    rv = pFunctionList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);

    if(rv == CKR_OK) {
        // Выполняем аутентификацию
        rv = pFunctionList->C_Login(hSession, CKU_USER, ((CK_UTF8CHAR_PTR)pin.c_str()), pin.size());
    }

    if(rv == CKR_OK) {
        args.GetReturnValue().Set(0);
    } else {
        args.GetReturnValue().Set((int)rv * -1);
    }
}
//
// Инициализация функций и модуля
//
void init(Handle<Object> exports) {
    NODE_SET_METHOD(exports, "initialize",       fnInitialize);
    NODE_SET_METHOD(exports, "isInitialize",     isInitialize);
	NODE_SET_METHOD(exports, "finalize",         fnFinalize);
    NODE_SET_METHOD(exports, "countSlot",        fnCountSlot);
    NODE_SET_METHOD(exports, "getSlotInfo",      fnGetSlotInfo);
    NODE_SET_METHOD(exports, "getTokenInfo",     fnGetTokenInfo);
    NODE_SET_METHOD(exports, "getMechanismList", fnGetMechanismList);
    NODE_SET_METHOD(exports, "login",            fnLogin);
}
NODE_MODULE(rutoken, init);
