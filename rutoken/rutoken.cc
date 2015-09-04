#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <Common.h>
#include <uv.h>
//#include <thread>
#include <string>
#include <config.h> // #define PKCS11ECP_LIBRARY_PATH для локального использования и добавлен в .gitignore

#define STR_LEN(s) (sizeof(s)/sizeof(s[0]))

using namespace v8;

bool bInitialize = false; // Флаг инициализации библиотеки PKCS#11 fnInitialize()
bool bLogin      = false; // Флаг аутентификации

HMODULE				          hModule         = NULL_PTR; // Хэндл загруженной библиотеки PKCS#11
CK_SESSION_HANDLE	          hSession        = NULL_PTR; // Хэндл открытой сессии
CK_FUNCTION_LIST_PTR          pFunctionList   = NULL_PTR; // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
CK_FUNCTION_LIST_EXTENDED_PTR pFunctionExList = NULL_PTR;

CK_SLOT_ID_PTR  aSlots      = NULL_PTR; // Указатель на массив идентификаторов всех доступных слотов
CK_ULONG        ulSlotCount = 0;        // Количество идентификаторов всех доступных слотов в массиве

DWORD i	  = 0;	       // Вспомогательная переменная-счетчик для циклов
CK_RV rv	 = CKR_OK; // Вспомогательная переменная для хранения кода возврата
CK_RV rvTemp = CKR_OK; // Вспомогательная переменная для хранения кода возврата

Local<String> _S(Isolate* isolate, const std::string& value) {
	return String::NewFromUtf8(isolate, value.c_str());
}
Local<String> _S(Isolate* isolate, const CK_UTF8CHAR_PTR value, int maxSize) {
	int len = maxSize;
	for (const char* p = (const char*)value + maxSize - 1; p >= (const char*)value && *p == 0x20; --p, --len) {}
	return String::NewFromUtf8(isolate, (const char*)value, String::kNormalString, len);
}
Local<Integer> _I(Isolate* isolate, int value) {
	return Integer::New(isolate, value);
}
Local<Object> _V(Isolate* isolate, const CK_VERSION& version) {
	Local<Object> ret = Object::New(isolate);
	ret->Set(_S(isolate, "major"), _I(isolate, (int)version.major));
	ret->Set(_S(isolate, "minor"), _I(isolate, (int)version.minor));
	return ret;
}

CK_RV _GetObjectLabel(CK_OBJECT_HANDLE hObject, std::string* out)
{
	CK_ATTRIBUTE attr[] = {
		{CKA_LABEL, NULL_PTR, 0}
	};

    std::string tmp;
    rv = pFunctionList->C_GetAttributeValue(hSession, hObject, attr, arraysize(attr));
    if(rv == CKR_OK && attr[0].ulValueLen)
	{
        tmp.resize(attr[0].ulValueLen);
        attr[0].pValue = &tmp[0];
        rv = pFunctionList->C_GetAttributeValue(hSession, hObject, attr, arraysize(attr));
    }
    out->swap(tmp);

    return rv;
}
CK_RV _GetObjectID(CK_OBJECT_HANDLE hObject, std::string* out)
{
	CK_ATTRIBUTE attr[] = {
		{CKA_ID, NULL_PTR, 0}
	};

	std::string tmp;
	rv = pFunctionList->C_GetAttributeValue(hSession, hObject, attr, arraysize(attr));
	if (rv == CKR_OK && attr[0].ulValueLen)
	{
		tmp.resize(attr[0].ulValueLen);
		attr[0].pValue = &tmp[0];
		rv = pFunctionList->C_GetAttributeValue(hSession, hObject, attr, arraysize(attr));
	}
	out->swap(tmp);

	return rv;
}

CK_RV checkInit()
{
	return bInitialize && pFunctionList != NULL_PTR ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

CK_RV checkArgs(const FunctionCallbackInfo<Value>& args, int requiredArgsLength)
{
	return args.Length() >= requiredArgsLength ? CKR_OK : CKR_ARGUMENTS_BAD;
}

CK_RV checkInitAndArgs(const FunctionCallbackInfo<Value>& args, int requiredArgsLength)
{
	CK_RV ret = checkInit();
	if (ret == CKR_OK)
		ret = checkArgs(args, requiredArgsLength);
	return ret;
}

CK_RV checkGetSlot(const FunctionCallbackInfo<Value>& args, int requiredArgsLength, int slotIdParamIndex, int* slotId)
{
	*slotId = 0;
	CK_RV ret = checkInitAndArgs(args, requiredArgsLength);

	if (ret == CKR_OK)
	{
		rv = CKR_SLOT_ID_INVALID;

		if (aSlots != NULL && slotIdParamIndex < requiredArgsLength)
		{
			Handle<Value> val = args[slotIdParamIndex];
			if (val->IsInt32())
			{
				int argSlotId = (int)val->ToInt32()->Int32Value();
				if (argSlotId >= 0 && argSlotId < (int)ulSlotCount)
				{
					*slotId = aSlots[argSlotId];
					ret = CKR_OK;
				}
			}
		}
	}

	return ret;
}

CK_RV checkGetSessionHandle(const FunctionCallbackInfo<Value>& args, int requiredArgsLength, int sessionHandleParamIndex, CK_SESSION_HANDLE_PTR sessionHandle)
{
	*sessionHandle = NULL;
	CK_RV ret = checkInitAndArgs(args, requiredArgsLength);

	if (ret == CKR_OK)
	{
		rv = CKR_SESSION_HANDLE_INVALID;

		if (sessionHandleParamIndex >= 0 && sessionHandleParamIndex < args.Length())
		{
			Handle<Value> val = args[sessionHandleParamIndex];
			if (val->IsNumber())
			{
				*sessionHandle = (CK_SESSION_HANDLE)val->IntegerValue();
				if (*sessionHandle != NULL)
					ret = CKR_OK;
			}
			else
				ret = CKR_ARGUMENTS_BAD;
		}
		else if (hSession != NULL)
		{
			*sessionHandle = hSession;
			ret = CKR_OK;
		}
	}

	return ret;
}

//
// Инициализация библиотеки rtPKCS11ECP
// Return: error (CKR_*)
//
void fnInitialize(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!bInitialize) {
		rv = CKR_FUNCTION_FAILED;

		// Шаг 1: Загрузить библиотеку.
		hModule = LoadLibrary(PKCS11ECP_LIBRARY_PATH);

		// Шаг 2: Получить адрес функции запроса структуры с указателями на функции.
		if (hModule != NULL_PTR) {

			// Указатель на функцию C_GetFunctionList
			CK_C_GetFunctionList            pfGetFunctionList   = (CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
			CK_C_EX_GetFunctionListExtended pfGetFunctionExList = (CK_C_EX_GetFunctionListExtended)GetProcAddress(hModule, "C_EX_GetFunctionListExtended");

			// Шаг 3: Получить структуру с указателями на функции.
			if (pfGetFunctionList != NULL_PTR && pfGetFunctionExList != NULL_PTR) {
				rv = pfGetFunctionList(&pFunctionList);
				rv = pfGetFunctionExList(&pFunctionExList);

				// Шаг 4: Инициализировать библиотеку.
				if (rv == CKR_OK) {
					rv = pFunctionList->C_Initialize(NULL_PTR);
					// Шаг 5: Установить флаг bInitialize = true.
					if (rv == CKR_OK) {
						bInitialize = true;
					}
				}
			}
		}
	}
	args.GetReturnValue().Set(-(int)rv);
}

//
// Возвращает флаг инициализации
// Return: bool
//
void isInitialize(const FunctionCallbackInfo<Value>& args) {
	args.GetReturnValue().Set(bInitialize);
}

//
// Выгружает библиотеку из памяти
// Return: error
//
void fnFinalize(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR) {
		rv = pFunctionList->C_Finalize(NULL_PTR);
		if (rv == CKR_OK) {
			bInitialize = false;
		}
	}

	args.GetReturnValue().Set(-(int)rv);
}

//
// Получает информацию о библиотеке
// Используется функция: C_GetInfo
// Return: error|object
//
void fnGetLibInfo(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 1)
		{
			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[0]);
			Local<Object>   object   = Object::New(isolate);

			CK_INFO info;
			int slot = aSlots[(int)args[0]->NumberValue()];

			rv = pFunctionList->C_GetInfo(&info);
			if (rv == CKR_OK)
			{
				object->Set(_S(isolate, "error"),              _I(isolate, -(int)rv));
				object->Set(_S(isolate, "cryptokiVersion"),    _V(isolate, info.cryptokiVersion));
				object->Set(_S(isolate, "manufacturerID"),     _S(isolate, info.manufacturerID, STR_LEN(info.manufacturerID)));
				object->Set(_S(isolate, "flags"),              _I(isolate, info.flags));
				object->Set(_S(isolate, "libraryDescription"), _S(isolate, info.libraryDescription, STR_LEN(info.manufacturerID)));
				object->Set(_S(isolate, "libraryVersion"),     _V(isolate, info.libraryVersion));

				Local<Value> argv[1] = { object };
				callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
				return;
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}
	}
    args.GetReturnValue().Set(-(int)rv);
}

//
// Количество зарегистрированных слотов (подключенных токенов) в системе
// Используется функция: C_GetSlotList
// Init: aSlots
// Return: error|int
//
void fnCountSlot(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
		if (rv == CKR_OK)
		{
			aSlots = (CK_SLOT_ID*)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
			memset(aSlots, 0, (ulSlotCount * sizeof(CK_SLOT_ID)));

			rv = pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulSlotCount);
			if (rv == CKR_OK)
			{
				args.GetReturnValue().Set((int)ulSlotCount);
            	return;
			}
		}
	}

	args.GetReturnValue().Set(-(int)rv);

}

//
// Получить информацию из слота
// Используется функция: C_GetSlotInfo
// Return: error|callback(data)
//
void fnGetSlotInfo(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SLOT_ID_INVALID;

			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[1]);
			Local<Object>   object   = Object::New(isolate);

			if (aSlots != NULL)
			{
				int arg0 = (int)args[0]->NumberValue();
				if (arg0 >= 0 && arg0 < (int)ulSlotCount)
				{
					CK_SLOT_INFO info;
					int slot = aSlots[(int)args[0]->NumberValue()];

					rv = pFunctionList->C_GetSlotInfo(slot, &info);
					if (rv == CKR_OK)
					{
						object->Set(_S(isolate, "error"),           _I(isolate, -(int)rv));
						object->Set(_S(isolate, "description"),     _S(isolate, info.slotDescription, STR_LEN(info.slotDescription)));
						object->Set(_S(isolate, "manufacturerID"),  _S(isolate, info.manufacturerID,  STR_LEN(info.manufacturerID)));
						object->Set(_S(isolate, "flags"),           _I(isolate, (int)info.flags));
						object->Set(_S(isolate, "hardwareVersion"), _V(isolate, info.hardwareVersion));
						object->Set(_S(isolate, "firmwareVersion"), _V(isolate, info.firmwareVersion));

						Local<Value> argv[1] = { object };
						callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
						return;
					}
				}
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}
	}
    args.GetReturnValue().Set(-(int)rv);
}

//
// Получить информацию из токена
// Используется функция: C_GetTokenInfo
// Return: error|callback(data)
//
void fnGetTokenInfo(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SLOT_ID_INVALID;

			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[1]);
			Local<Object>   object   = Object::New(isolate);

			if (aSlots != NULL)
			{
				int arg0 = (int)args[0]->NumberValue();
				if (arg0 >= 0 && arg0 < (int)ulSlotCount)
				{
					CK_TOKEN_INFO info;
					int slot = aSlots[(int)args[0]->NumberValue()];

					rv = pFunctionList->C_GetTokenInfo(slot, &info);
					if (rv == CKR_OK)
					{
						object->Set(_S(isolate, "label"),              _S(isolate, info.label, STR_LEN(info.label)));
						object->Set(_S(isolate, "manufacturerID"),     _S(isolate, info.manufacturerID, STR_LEN(info.manufacturerID)));
						object->Set(_S(isolate, "model"),              _S(isolate, info.model, STR_LEN(info.model)));
						object->Set(_S(isolate, "serialNumber"),       _S(isolate, info.serialNumber, STR_LEN(info.serialNumber)));
						object->Set(_S(isolate, "flags"),              _I(isolate, (int)info.flags));
						object->Set(_S(isolate, "maxSessionCount"),    _I(isolate, (int)info.ulMaxSessionCount));
						object->Set(_S(isolate, "sessionCount"),       _I(isolate, (int)info.ulSessionCount));
						object->Set(_S(isolate, "maxRwSessionCount"),  _I(isolate, (int)info.ulMaxRwSessionCount));
						object->Set(_S(isolate, "rwSessionCount"),     _I(isolate, (int)info.ulRwSessionCount));
						object->Set(_S(isolate, "maxPinLen"),          _I(isolate, (int)info.ulMaxPinLen));
						object->Set(_S(isolate, "minPinLen"),          _I(isolate, (int)info.ulMinPinLen));
						object->Set(_S(isolate, "totalPublicMemory"),  _I(isolate, (int)info.ulTotalPublicMemory));
						object->Set(_S(isolate, "freePublicMemory"),   _I(isolate, (int)info.ulFreePublicMemory));
						object->Set(_S(isolate, "totalPrivateMemory"), _I(isolate, (int)info.ulTotalPrivateMemory));
						object->Set(_S(isolate, "freePrivateMemory"),  _I(isolate, (int)info.ulFreePrivateMemory));
						object->Set(_S(isolate, "hardwareVersion"),    _V(isolate, info.hardwareVersion));
						object->Set(_S(isolate, "firmwareVersion"),    _V(isolate, info.firmwareVersion));
						object->Set(_S(isolate, "utcTime"),            _S(isolate, info.utcTime, STR_LEN(info.utcTime)));

						Local<Value> argv[1] = { object };
						callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
						return;
					}
				}
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}
	}
    args.GetReturnValue().Set(-(int)rv);
}

//
// Получить список доступных механизмов токена
// Используется функция: C_GetMechanismList
// Return: error|callback
//
void fnGetMechanismList(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SLOT_ID_INVALID;

			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[1]);
			Local<Object>   object   = Object::New(isolate);

			if (aSlots != NULL)
			{
				int arg0 = (int)args[0]->NumberValue();
				if (arg0 >= 0 && arg0 < (int)ulSlotCount)
				{
					CK_MECHANISM_INFO     info;
					CK_ULONG              ulMechanismCount = 0;
					CK_MECHANISM_TYPE_PTR aMechanisms = NULL_PTR;

					int slot = aSlots[(int)args[0]->NumberValue()];

					rv = pFunctionList->C_GetMechanismList(slot, NULL_PTR, &ulMechanismCount);

					if(rv == CKR_OK)
					{
						aMechanisms = (CK_MECHANISM_TYPE*)malloc(sizeof(CK_MECHANISM_TYPE) * ulMechanismCount);
						memset(aMechanisms, 0, (sizeof(CK_MECHANISM_TYPE) * ulMechanismCount));
						rv = pFunctionList->C_GetMechanismList(slot, aMechanisms, &ulMechanismCount);

						if(rv == CKR_OK)
						{
							Local<Array> arr = Array::New(isolate);

							object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
							object->Set(_S(isolate, "count"), _I(isolate, (int)ulMechanismCount));
							object->Set(_S(isolate, "list"), arr);

							for (i = 0; i < ulMechanismCount; i++)
							{
								memset(&info, 0, sizeof(CK_MECHANISM_INFO));
								rv = pFunctionList->C_GetMechanismInfo(slot, aMechanisms[i], &info);
								if (rv == CKR_OK)
								{
									Local<Object> objM = Object::New(isolate);
									objM->Set(_S(isolate, "type"),	     _I(isolate, (int)aMechanisms[i]));
									objM->Set(_S(isolate, "minKeySize"), _I(isolate, (int)info.ulMinKeySize));
									objM->Set(_S(isolate, "maxKeySize"), _I(isolate, (int)info.ulMaxKeySize));
									objM->Set(_S(isolate, "flags"),	     _I(isolate, (int)info.flags));
									arr->Set(i, objM);
								} else {
									break;
								}
							}

							Local<Value> argv[1] = { object };
							callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
							return;
						}
					}
				}
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}
	}
    args.GetReturnValue().Set(-(int)rv);
}

//
// Получает список объектов токена
// Используются функции: C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal
// Return: error|callback
//
void fnGetObjectList(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 1)
		{
			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[0]);
			Local<Object>   object   = Object::New(isolate);

			CK_ATTRIBUTE attr[] = {
				{CKA_CLASS, &ocPubKey, sizeof(ocPubKey)}
			};

			rv = pFunctionList->C_FindObjectsInit(hSession, attr, arraysize(attr));
			if(rv == CKR_OK)
			{
				CK_ULONG         count;
				CK_OBJECT_HANDLE hPublicKey;

				rv = pFunctionList->C_FindObjects(hSession, &hPublicKey, 1, &count);
				if(rv == CKR_OK)
				{
					Local<Array> arr = Array::New(isolate);
					i = 0;
					while (rv == CKR_OK && count)
					{
						i++;
						Local<Object> tmpObj = Object::New(isolate);

						std::string label;
            			rv = _GetObjectLabel(hPublicKey, &label);
            			if(rv == CKR_OK) {
							tmpObj->Set(_S(isolate, "label"), _S(isolate, label));
            			}

						std::string id;
            			rv = _GetObjectID(hPublicKey, &id);
            			if(rv == CKR_OK) {
							tmpObj->Set(_S(isolate, "id"), _S(isolate, id));
            			}

						rv = pFunctionList->C_FindObjects(hSession, &hPublicKey, 1, &count);

						arr->Set(i-1, tmpObj);
					}

					object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
					object->Set(_S(isolate, "count"), _I(isolate, i));
					object->Set(_S(isolate, "list"), arr);

					Local<Value> argv[1] = { object };
					callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
					return;
				}
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}

	}
	args.GetReturnValue().Set(-(int)rv);
}
//
// Функция открывает сессию и авторизует пользователя на токене.
//
void fnLogin(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SLOT_ID_INVALID;

			if (aSlots != NULL)
			{
				int arg0 = (int)args[0]->NumberValue();
				if (arg0 >= 0 && arg0 < (int)ulSlotCount)
				{
					int slot = aSlots[arg0];
					String::Utf8Value pin(args[1]->ToString());

					rv = pFunctionList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);

					if(rv == CKR_OK) {
						rv = pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)*pin, pin.length());
						//rv = pFunctionList->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)*pin, pin.length()); // Admin
						if(rv == CKR_OK) {
							// Возвращает CKR_USER_NOT_LOGGED_IN
							//rv = pFunctionExList->C_EX_UnblockUserPIN(hSession);
						}
					}
				}
			}
		}
	}
	args.GetReturnValue().Set(-(int)rv);
}

//
// random(size, callback(res))
// Генерирует случайное число размером size
// Возвращает объект или код ошибки
//
void fnRandom(const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SESSION_HANDLE_INVALID;

			Isolate* isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);

			Local<Function> callback = Local<Function>::Cast(args[1]);
			Local<Object>   object   = Object::New(isolate);

			if(hSession != NULL_PTR)
			{
				CK_ULONG size = (CK_ULONG)args[0]->NumberValue();
				CK_BYTE *randomData = new CK_BYTE[size];

				rv = pFunctionList->C_GenerateRandom(hSession, randomData, size);
				if (rv == CKR_OK) {

					Local<Array> arrInt = Array::New(isolate);
					Local<Array> arrHex = Array::New(isolate);

					for (i = 0; i < size; i++) {
						// Int array
						arrInt->Set(i, _I(isolate, randomData[i]));

						// Hex array
						char buffer[2];
						sprintf(buffer, "%02x", randomData[i]);
						arrHex->Set(i, _S(isolate, buffer));
					}

					object->Set(_S(isolate, "error"),  _I(isolate, -(int)rv));
					object->Set(_S(isolate, "length"), _I(isolate, size));
					object->Set(_S(isolate, "int"),    arrInt);
					object->Set(_S(isolate, "hex"),    arrHex);

					Local<Value> argv[1] = { object };
					callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
					return;
				}
			}

			object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
			Local<Value> argv[1] = { object };
			callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
			return;
		}
	}
    args.GetReturnValue().Set(-(int)rv);
}

//
// Инициализирует память Рутокен со стандартными параметрами
// Используется функция: C_EX_InitToken
//
/*
struct stInitToken
{
    int result;
	int slot;
    Persistent<Object> callback;
};
void thInitTokenWorker(uv_work_t* req)
{

}
void thInitTokenAfter(uv_work_t* req, int status)
{
	Isolate* isolate = Isolate::GetCurrent();

	stInitToken* request = (stInitToken*)req->data;
	delete req;

	Handle<Value> argv[2];
	argv[0] = Integer::New(isolate, request->result);

	//request->callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);

}
*/
void thInitToken(Isolate* isolate, const FunctionCallbackInfo<Value>& args)
{
	rv = CKR_SLOT_ID_INVALID;

	Local<Function> callback = Local<Function>::Cast(args[1]);
	Local<Object>   object   = Object::New(isolate);

	if (aSlots != NULL)
	{
		int arg0 = (int)args[0]->NumberValue();
		if (arg0 >= 0 && arg0 < (int)ulSlotCount)
		{
			int    slot                      = aSlots[arg0];
			static CK_CHAR     TOKEN_LABEL[] = {"RutokenJS"};
			static CK_UTF8CHAR USER_PIN[]    = {'1', '2', '3', '4', '5', '6', '7', '8'};
			static CK_UTF8CHAR ADMIN_PIN[]   = {'8', '7', '6', '5', '4', '3', '2', '1'};

			CK_RUTOKEN_INIT_PARAM initInfo_st;
			initInfo_st.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM);
			initInfo_st.UseRepairMode         = 0;
			initInfo_st.pNewAdminPin          = ADMIN_PIN;
			initInfo_st.ulNewAdminPinLen      = sizeof(ADMIN_PIN);
			initInfo_st.pNewUserPin           = USER_PIN;
			initInfo_st.ulNewUserPinLen       = sizeof(USER_PIN);
			initInfo_st.ulMinAdminPinLen      = 8;
			initInfo_st.ulMinUserPinLen       = 8;
			initInfo_st.ChangeUserPINPolicy   = (TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN);
			initInfo_st.ulMaxAdminRetryCount  = 10;
			initInfo_st.ulMaxUserRetryCount   = 10;
			initInfo_st.pTokenLabel           = TOKEN_LABEL;
			initInfo_st.ulLabelLen            = sizeof(TOKEN_LABEL);

			rv = pFunctionExList->C_EX_InitToken(slot, ADMIN_PIN, arraysize(ADMIN_PIN), &initInfo_st);
		}
	}

	object->Set(_S(isolate, "error"), _I(isolate, -(int)rv));
	Local<Value> argv[1] = { object };
	callback->Call(isolate->GetCurrentContext()->Global(), 1, argv);
	return;
}
void fnInitToken(const FunctionCallbackInfo<Value>& args)
{
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);

	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (bInitialize && pFunctionList != NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;

		if (args.Length() == 2)
		{
			rv = CKR_SLOT_ID_INVALID;

			if (aSlots != NULL)
			{
				int arg0 = (int)args[0]->NumberValue();
				if (arg0 >= 0 && arg0 < (int)ulSlotCount)
				{
					/*
					int slot = aSlots[arg0];
					Local<Function>      callback = Local<Function>::Cast(args[1]);
					Persistent<Object> prCallback(isolate, args[1]);

					//Persistent<Function, CopyablePersistentTraits<Function>> f(isolate, callback);

					stInitToken* request = new stInitToken();
					request->callback = prCallback;
					request->slot     = slot;

					uv_work_t* req = new uv_work_t();
					req->data = request;
					uv_queue_work(uv_default_loop(), req, thInitTokenWorker, thInitTokenAfter);
					*/
				}
			}

			//Isolate* isolate = Isolate::GetCurrent();
			thInitToken(isolate, args);
			// Попытка запустить в отдельном потоке приводит к падению приложения... (((
			//std::thread thr(thInitToken, isolate, args);
			//thr.detach();
		}
	}
	args.GetReturnValue().Set(-(int)rv);
}

//
// Открывает новую сессию с Рутокен
//
void fnOpenSession(const FunctionCallbackInfo<Value>& args)
{
	int slotId = 0;
	CK_RV ret = checkGetSlot(args, 1, 0, &slotId);
	if (ret == CKR_OK)
	{
		CK_SESSION_HANDLE handle = NULL;
		ret = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &handle);

		if (ret == CKR_OK)
		{
			args.GetReturnValue().Set((unsigned int)handle);
			return;
		}
	}

	args.GetReturnValue().Set(-(int)ret);
}

//
// Закрывает сессию с Рутокен
//
void fnCloseSession(const FunctionCallbackInfo<Value>& args)
{
	CK_SESSION_HANDLE handle = NULL;
	CK_RV ret = checkGetSessionHandle(args, 0, 0, &handle);
	if (ret == CKR_OK)
		ret = pFunctionList->C_CloseSession(handle);

	args.GetReturnValue().Set(-(int)ret);
}

//
// Закрывает все сессии
//
void fnCloseAllSessions(const FunctionCallbackInfo<Value>& args)
{
	int slotId = 0;
	CK_RV ret = checkGetSlot(args, 1, 0, &slotId);
	if (ret == CKR_OK)
		ret = pFunctionList->C_CloseAllSessions(slotId);

	args.GetReturnValue().Set(-(int)ret);
}

//
// Получает информацию о конкретной сессии
//
void fnGetSessionInfo(const FunctionCallbackInfo<Value>& args)
{
	CK_SESSION_HANDLE handle = NULL;
	CK_RV ret = checkGetSessionHandle(args, 0, 0, &handle);
	if (ret == CKR_OK)
	{
		CK_SESSION_INFO info;
		ret = pFunctionList->C_GetSessionInfo(handle, &info);
		if (ret == CKR_OK)
		{
			Isolate*    isolate = Isolate::GetCurrent();
			HandleScope scope(isolate);
			Local<Object>   object = Object::New(isolate);
			object->Set(_S(isolate, "slotId"      ), _I(isolate, info.slotID       ));
			object->Set(_S(isolate, "state"       ), _I(isolate, info.state        ));
			object->Set(_S(isolate, "flags"       ), _I(isolate, info.flags        ));
			object->Set(_S(isolate, "deviceError" ), _I(isolate, info.ulDeviceError));
			args.GetReturnValue().Set(object);
			return;
		}
	}

	args.GetReturnValue().Set(-(int)ret);
}

//
// Получает информацию о состоянии выполнения криптографической операции
//
void fnGetOperationState(const FunctionCallbackInfo<Value>& args)
{
	CK_SESSION_HANDLE handle = NULL;
	CK_RV ret = checkGetSessionHandle(args, 0, 0, &handle);
	if (ret == CKR_OK)
	{
		CK_ULONG operStateLen = 0;
		ret = pFunctionList->C_GetOperationState(handle, NULL, &operStateLen);
		if (ret == CKR_OK && operStateLen > 0)
		{
			CK_BYTE_PTR pState = new CK_BYTE[operStateLen];
			ret = pFunctionList->C_GetOperationState(handle, pState, &operStateLen);
			if (ret == CKR_OK)
			{
				Isolate*    isolate = Isolate::GetCurrent();
				HandleScope scope(isolate);
				Local<Array> arr = Array::New(isolate, operStateLen);
				for (CK_ULONG i = 0; i < operStateLen; ++i)
					arr->Set(i, _I(isolate, pState[i]));
				args.GetReturnValue().Set(arr);
				return;
			}

			delete[] pState;
		}
	}

	args.GetReturnValue().Set(-(int)ret);
}

//
// Изменяет состояние выполнения криптографической операции
//
void fnSetOperationState(const FunctionCallbackInfo<Value>& args)
{
	CK_SESSION_HANDLE handle = NULL;
	CK_RV ret = checkGetSessionHandle(args, 3, 3, &handle);
	if (ret == CKR_OK)
	{
		if (args[0]->IsArray() && args[1]->IsInt32() && args[2]->Int32Value())
		{
			Handle<Array> arg0 = Handle<Array>::Cast(args[0]);
			CK_ULONG operStateLen = arg0->Length();
			if (operStateLen > 0)
			{
				CK_OBJECT_HANDLE hEncryptionKey     = (CK_ULONG)args[1]->IntegerValue();
				CK_OBJECT_HANDLE hAuthenticationKey = (CK_ULONG)args[2]->IntegerValue();

				CK_BYTE_PTR pState = new CK_BYTE[operStateLen];
				for (CK_ULONG i = 0; i < operStateLen; ++i)
					pState[i] = (CK_BYTE)arg0->Get(i)->NumberValue();

				ret = pFunctionList->C_SetOperationState(handle, pState, operStateLen, hEncryptionKey, hAuthenticationKey);

				delete pState;
			}
			else
				ret = CKR_ARGUMENTS_BAD;
		}
		else
			ret = CKR_ARGUMENTS_BAD;
	}

	args.GetReturnValue().Set(-(int)ret);
}

//
// Выполняет выход пользователя / администратора
//
void fnLogout(const FunctionCallbackInfo<Value>& args)
{
	CK_SESSION_HANDLE handle = NULL;
	CK_RV ret = checkGetSessionHandle(args, 0, 0, &handle);
	if (ret == CKR_OK)
		ret = pFunctionList->C_Logout(handle);

	args.GetReturnValue().Set(-(int)ret);
}

//
//
//

//
// Инициализация функций и модуля
//
void init(Handle<Object> exports) {
	NODE_SET_METHOD(exports, "initialize",       fnInitialize);
	NODE_SET_METHOD(exports, "isInitialize",     isInitialize);
    NODE_SET_METHOD(exports, "finalize",         fnFinalize);
	NODE_SET_METHOD(exports, "getLibInfo",       fnGetLibInfo);
	NODE_SET_METHOD(exports, "countSlot",        fnCountSlot);
	NODE_SET_METHOD(exports, "getSlotInfo",      fnGetSlotInfo);
	NODE_SET_METHOD(exports, "getTokenInfo",     fnGetTokenInfo);
	NODE_SET_METHOD(exports, "getMechanismList", fnGetMechanismList);
	NODE_SET_METHOD(exports, "getObjectList",    fnGetObjectList);
	NODE_SET_METHOD(exports, "random",           fnRandom);
	NODE_SET_METHOD(exports, "initToken",        fnInitToken);
	// sessions
	NODE_SET_METHOD(exports, "openSession"      , fnOpenSession);
	NODE_SET_METHOD(exports, "closeSession"     , fnCloseSession);
	NODE_SET_METHOD(exports, "closeAllSessions" , fnCloseAllSessions);
	NODE_SET_METHOD(exports, "getSessionInfo"   , fnGetSessionInfo);
	NODE_SET_METHOD(exports, "setOperationState", fnSetOperationState);
	NODE_SET_METHOD(exports, "getOperationState", fnGetOperationState);
	NODE_SET_METHOD(exports, "login"            , fnLogin);
	NODE_SET_METHOD(exports, "logout"           , fnLogout);
}
NODE_MODULE(rutoken, init);
