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
CK_C_GetFunctionList pfGetFunctionList = NULL_PTR; // Указатель на функцию C_GetFunctionList

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
// Метод вызывается в методе init
//
void fnInitialize(const FunctionCallbackInfo<Value>& args) {
    // Шаг 1: Загрузить библиотеку.
    hModule = LoadLibrary("rtPKCS11ECP.dll");

    // Шаг 2: Получить адрес функции запроса структуры с указателями на функции.
    if (hModule != NULL_PTR) {
        pfGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
    }

    // Шаг 3: Получить структуру с указателями на функции.
    if (pfGetFunctionList != NULL_PTR) {
        rv = pfGetFunctionList(&pFunctionList);
    }

    // Шаг 4: Инициализировать библиотеку.
    if(rv == CKR_OK) {
        rv = pFunctionList->C_Initialize(NULL_PTR);
    }

    // Шаг 5: Установить флаг isDLL = true.
    if(rv == CKR_OK) {
        bInitialize = true;
    }

    args.GetReturnValue().Set(bInitialize);
}
void isInitialize(const FunctionCallbackInfo<Value>& args) {
    args.GetReturnValue().Set(bInitialize);
}

//
// Количество зарегистрированных слотов (подключенных токенов) в системе
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
// C_GetSlotInfo
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
        obj->Set(_S(isolate, "slotDescription"), _S(isolate, str.substr(0, (int)sizeof(slotInfo.slotDescription))));

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
// C_GetTokenInfo
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
// C_GetMechanismList
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

        }
    } else {

    }

}

//
// Initializing Module
//
void init(Handle<Object> exports) {
    NODE_SET_METHOD(exports, "fnInitialize",       fnInitialize);
    NODE_SET_METHOD(exports, "isInitialize",       isInitialize);
    NODE_SET_METHOD(exports, "fnCountSlot",        fnCountSlot);
    NODE_SET_METHOD(exports, "fnGetSlotInfo",      fnGetSlotInfo);
    NODE_SET_METHOD(exports, "fnGetTokenInfo",     fnGetTokenInfo);
    NODE_SET_METHOD(exports, "fnGetMechanismList", fnGetMechanismList);
}
NODE_MODULE(rutoken, init);
