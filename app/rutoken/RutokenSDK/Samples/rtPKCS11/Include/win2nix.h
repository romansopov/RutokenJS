/*************************************************************************
* Rutoken                                                                *
* Copyright (C) Aktiv Co. 2003 - 2014                                    *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Данный файл содержит переопределение функций Windows для               *
* *nix-платформ                                                          *
*************************************************************************/

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define RUTOKENECP
#define TOKEN
#define FAST
#define RSAMODULUSBITS 1024
#define RSA

#ifdef _WIN32

__inline uintptr_t CreateProc(void *thread,  unsigned int size, void (__cdecl * funct) (void *), void *arg)
{
	return _beginthread(funct, size, arg);
}

#endif

#if defined(__unix__) || defined(__APPLE__)

#include <dlfcn.h>
#include <sys/time.h>
#include <pthread.h>

typedef void* HMODULE;

static inline HMODULE LoadLibrary(const char* path)
{
	return dlopen(path, RTLD_NOW);
}

static inline unsigned long GetTickCount(void)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0)
		return 0;
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static inline BOOL FreeLibrary(HMODULE module)
{
	// return value is inverted in order to correspond to Windows behavior:
	return (! dlclose(module)); 
}

static inline ptrdiff_t GetProcAddress(HMODULE module, const char* proc_name)
{
	return (ptrdiff_t)(dlsym(module, proc_name));
}

#define uintptr_t pthread_t

static inline uintptr_t CreateProc(uintptr_t *thread, pthread_attr_t *attr, void *funct, void *arg)
{
	pthread_create(thread, attr, funct, arg);
	return *thread;
}



#ifdef __APPLE__
const char DEFAULTLIBRARYNAME[] = "./librtpkcs11ecp.dylib";
#else
const char DEFAULTLIBRARYNAME[] = "./librtpkcs11ecp.so";
#endif

#endif // __unix__ || __APPLE__



