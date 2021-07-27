// dllmain.h: 模块类的声明。

class CspaceshipsvrModule : public ATL::CAtlDllModuleT< CspaceshipsvrModule >
{
public :
	DECLARE_LIBID(LIBID_spaceshipsvrLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_SPACESHIPSVR, "{c1b1ca83-b9bf-4e99-8be6-cc5d16b62570}")
};

extern class CspaceshipsvrModule _AtlModule;
