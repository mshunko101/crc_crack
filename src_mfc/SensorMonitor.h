
// display.h: главный файл заголовка для приложения PROJECT_NAME
//

#pragma once

#ifndef __AFXWIN_H__
	#error "включить pch.h до включения этого файла в PCH"
#endif

#include "resource.h"		// основные символы


// CdisplayApp:
// Сведения о реализации этого класса: display.cpp
//

class CdisplayApp : public CWinApp
{
public:
	CdisplayApp();

// Переопределение
public:
	virtual BOOL InitInstance();

// Реализация

	DECLARE_MESSAGE_MAP()
};

extern CdisplayApp theApp;
