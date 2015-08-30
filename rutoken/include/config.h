#ifndef Config_H
#define Config_H

#include "Common.h"

#define WORK_DIR "D:/Projects/RutokenJS/"

/* Имя библиотеки PKCS#11 */
#ifdef _WIN32
#define PKCS11_RELATIVE_LIBRARY_PATH "rutoken/libs/windows/x64/" 
#endif 
#ifdef __unix__
#define PKCS11_RELATIVE_LIBRARY_PATH "rutoken/libs/linux/x86_64/"
#endif 	
#ifdef __APPLE__
#define PKCS11_RELATIVE_LIBRARY_PATH "rutoken/libs/mac/"
#endif 

#define PKCS11ECP_LIBRARY_PATH    WORK_DIR PKCS11_RELATIVE_LIBRARY_PATH PKCS11ECP_LIBRARY_NAME

#endif //Config_H