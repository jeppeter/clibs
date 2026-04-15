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

#include <vector>
#include <map>


class  ExpClass {
public:
	CLASSIMPORT ExpClass();
	CLASSIMPORT virtual ~ExpClass();
	CLASSIMPORT int print_hello(char* name);
	CLASSIMPORT int put_i(int i);
	CLASSIMPORT int put_map_i(int i, int j);
private:
	std::vector<int> m_vis;
	std::map<int,int> m_mis;
};
#pragma warning(pop)

#endif /* __CLASS_H_043BBC4E06348741508918DE09FE189F__ */
