#ifndef __CLASS_H_043BBC4E06348741508918DE09FE189F__
#define __CLASS_H_043BBC4E06348741508918DE09FE189F__

#if defined(CLASS_DLL_EXPORT)
#define CLASSIMPORT __declspec(dllexport)
#elif  defined(CLASS_DLL_IMPORT)
#define CLASSIMPORT __declspec(dllimport)
#else
#define CLASSIMPORT
#endif


#pragma warning(push)
#pragma warning(disable:5045)


class CLASSIMPORT ExpClass {
public:
	ExpClass();
	virtual ~ExpClass();
	int print_hello(char* name);
};
#pragma warning(pop)

#endif /* __CLASS_H_043BBC4E06348741508918DE09FE189F__ */
