#pragma once

#ifndef _STDAFX_H__
#define _STDAFX_H__

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers
#define _AFXDLL

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxdisp.h>        // MFC Automation classes
#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls

#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif

#include <comdef.h>			// For _bstr_t and COM interfaces
#include <wbemidl.h>		// For WMI interfaces
#pragma comment(lib, "wbemuuid.lib") // Link WMI library

#endif // !_STDAFX_H__
