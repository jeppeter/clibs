#! /usr/bin/env python


import logging
import re
import extargsparse
import sys
import os
import json

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
import fileop


def init_propmaps():
    newmaps = dict()
    newmaps['system.devices.modelid'] = ( '80d81ea6-7473-4b0c-8216-efc11a2c4c8b',2 )
    newmaps['system.devices.modelname'] = ( '656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8194 )
    newmaps['system.devices.modelnumber'] = ( '656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8195 )
    newmaps['system.devices.friendlyname'] = ( '656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12288 )
    newmaps['system.itemnamedisplay'] = ( 'b725f130-47ef-101a-a5f1-02608c9eebac',10 )
    newmaps['system.devices.devnodestatus'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',2 )
    newmaps['system.devices.problemcode'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',3 )
    newmaps['system.devices.ejectionrelations'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',4 )
    newmaps['system.devices.removalrelations'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',5 )
    newmaps['system.devices.powerrelations'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',6 )
    newmaps['system.devices.busrelations'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',7 )
    newmaps['system.devices.parent'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',8 )
    newmaps['system.devices.children'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',9 )
    newmaps['system.devices.siblings'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',10 )
    newmaps['system.devices.transportrelations'] = ( '4340a6c5-93fa-4706-972c-7b648008a5a7',11 )
    newmaps['system.devices.networkname'] = ( '49cd1f76-5626-4b17-a4e8-18b4aa1a2213',7 )
    newmaps['system.devices.networktype'] = ( '49cd1f76-5626-4b17-a4e8-18b4aa1a2213',8 )
    newmaps['system.devices.model'] = ( '78c34fc8-104a-4aca-9ea4-524d52996e57',39 )
    newmaps['system.devices.instanceid'] = ( '78c34fc8-104a-4aca-9ea4-524d52996e57',256 )
    newmaps['system.devices.description'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',2 )
    newmaps['system.devices.hardwareids'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',3 )
    newmaps['system.devices.compatibleids'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',4 )
    newmaps['system.devices.service'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',6 )
    newmaps['system.devices.class'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',9 )
    newmaps['system.devices.classguid'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',10 )
    newmaps['system.devices.driver'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',11 )
    newmaps['system.devices.configflags'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',12 )
    newmaps['system.devices.manufacturer'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',13 )
    newmaps['system.devices.friendlyname'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',14 )
    newmaps['system.devices.locationinfo'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',15 )
    newmaps['system.devices.pdoname'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',16 )
    newmaps['system.devices.capabilities'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',17 )
    newmaps['system.devices.uinumber'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',18 )
    newmaps['system.devices.upperfilters'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',19 )
    newmaps['system.devices.lowerfilters'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',20 )
    newmaps['system.devices.bustypeguid'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',21 )
    newmaps['system.devices.legacybustype'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',22 )
    newmaps['system.devices.busnumber'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',23 )
    newmaps['system.devices.enumeratorname'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',24 )
    newmaps['system.devices.security'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',25 )
    newmaps['system.devices.securitysds'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',26 )
    newmaps['system.devices.devtype'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',27 )
    newmaps['system.devices.exclusive'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',28 )
    newmaps['system.devices.characteristics'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',29 )
    newmaps['system.devices.address'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',30 )
    newmaps['system.devices.uinumberdescformat'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',31 )
    newmaps['system.devices.powerdata'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',32 )
    newmaps['system.devices.removalpolicy'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',33 )
    newmaps['system.devices.removalpolicydefault'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',34 )
    newmaps['system.devices.removalpolicyoverride'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',35 )
    newmaps['system.devices.installstate'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',36 )
    newmaps['system.devices.locationpaths'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',37 )
    newmaps['system.devices.basecontainerid'] = ( 'a45c254e-df1c-4efd-8020-67d146a850e0',38 )
    newmaps['system.drivers.assemblydate'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',2 )
    newmaps['system.drivers.version'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',3 )
    newmaps['system.drivers.description'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',4 )
    newmaps['system.drivers.infpath'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',5 )
    newmaps['system.drivers.infsection'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',6 )
    newmaps['system.drivers.infsectionext'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',7 )
    newmaps['system.drivers.matchingdeviceid'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',8 )
    newmaps['system.drivers.provider'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',9 )
    newmaps['system.drivers.proppageprovider'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',10 )
    newmaps['system.drivers.coinstallers'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',11 )
    newmaps['system.drivers.resourcepickertags'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',12 )
    newmaps['system.drivers.resourcepickerexceptions'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',13 )
    newmaps['system.drivers.rank'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',14 )
    newmaps['system.drivers.logolevel'] = ( 'a8b865dd-2e3d-4094-ad97-e593a70c75d6',15 )
    newmaps['system.devices.numaproximitydomain'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',2 )
    newmaps['system.devices.dhprebalancepolicy'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',3 )
    newmaps['system.devices.numanode'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',4 )
    newmaps['system.devices.busreporteddevicedesc'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',5 )
    newmaps['system.devices.ispresent'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',5 )
    newmaps['system.devices.hasproblem'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',6 )
    newmaps['system.devices.configurationid'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',7 )
    newmaps['system.devices.reporteddeviceidshash'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',8 )
    newmaps['system.devices.physicaldevicelocation'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',9 )
    newmaps['system.devices.biosdevicename'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',10 )
    newmaps['system.devices.driverproblemdesc'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',11 )
    newmaps['system.devices.debuggersafe'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',12 )
    newmaps['system.devices.postinstallinprogress'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',13 )
    newmaps['system.devices.stack'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',14 )
    newmaps['system.devices.extendedconfigurationids'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',15 )
    newmaps['system.devices.isrebootrequired'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',16 )
    newmaps['system.devices.firmwaredate'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',17 )
    newmaps['system.devices.firmwareversion'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',18 )
    newmaps['system.devices.firmwarerevision'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',19 )
    newmaps['system.devices.dependencyproviders'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',20 )
    newmaps['system.devices.dependencydependents'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',21 )
    newmaps['system.devices.softrestartsupported'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',22 )
    newmaps['system.devices.extendedaddress'] = ( '540b947e-8b40-45bc-a8a2-6a0b894cbda2',23 )
    newmaps['system.devices.sessionid'] = ( '83da6326-97a6-4088-9453-a1923f573b29',6 )
    newmaps['system.devices.installdate'] = ( '83da6326-97a6-4088-9453-a1923f573b29',100 )
    newmaps['system.devices.firstinstalldate'] = ( '83da6326-97a6-4088-9453-a1923f573b29',101 )
    newmaps['system.devices.lastarrivaldate'] = ( '83da6326-97a6-4088-9453-a1923f573b29',102 )
    newmaps['system.devices.lastremovaldate'] = ( '83da6326-97a6-4088-9453-a1923f573b29',103 )
    newmaps['system.devices.containerid'] = ('8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c',2)
    newmaps['system.devices.saferemovalrequired'] = ('afd97640-86a3-4210-b67c-289c41aabe55',2)

    newmaps['system.pci.devicetype'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',1)
    newmaps['system.pci.currentspeedandmode'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',2)
    newmaps['system.pci.baseclass'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',3)
    newmaps['system.pci.subclass'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',4)
    newmaps['system.pci.progif'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',5)
    newmaps['system.pci.interruptsupport'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',14)
    newmaps['system.pci.bartypes'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',16)
    newmaps['system.pci.s0wakeupsupported'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',25)
    newmaps['system.pci.driverinfo'] = ('83da6326-97a6-4088-9453-a1923f573b29',3)
    newmaps['system.pci.upperdriverinfo'] = ('83da6326-97a6-4088-9453-a1923f573b29',4)
    newmaps['system.driver.upperfile'] = ('a8b865dd-2e3d-4094-ad97-e593a70c75d6',16)
    newmaps['system.driver.upperconfig'] = ('f0e20f09-d97a-49a9-8046-bb6e22e6bb2e',2)
    newmaps['system.devices.modelcfg'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',28672)
    newmaps['system.devices.modelver'] = ('80d81ea6-7473-4b0c-8216-efc11a2c4c8b',3)
    newmaps['system.driver.unknown1'] = ('a8b865dd-2e3d-4094-ad97-e593a70c75d6',17)
    newmaps['system.usb.unknown1'] = ('c4f6821f-52d5-44c5-a674-4a07f1b60d4c',3)
    newmaps['system.usb.unknown2'] = ('e5c2ac63-e4d6-4d35-9c5e-53e9dc6003af',1)
    newmaps['system.usb.unknown3'] = ('80497100-8c73-48b9-aad9-ce387e19c56e',3)
    newmaps['system.unknown.unknown1'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',10)
    newmaps['system.unknown.unknown2'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',11)
    newmaps['system.unknown.unknown3'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',12)
    newmaps['system.unknown.unknown4'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',13)
    newmaps['system.unknown.unknown5'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',15)
    newmaps['system.unknown.unknown6'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',17)
    newmaps['system.unknown.unknown7'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',6)
    newmaps['system.unknown.unknown8'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',7)
    newmaps['system.unknown.unknown9'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',8)
    newmaps['system.unknown.unknown10'] = ('3ab22e31-8264-4b4e-9af5-a8d2d8e33e62',9)
    newmaps['system.unknown.unknown11'] = ('5724c81d-d5af-4c1f-a103-a06e28f204c6',1)
    newmaps['system.unknown.unknown12'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12288)
    newmaps['system.unknown.unknown13'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12289)
    newmaps['system.unknown.unknown14'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12290)
    newmaps['system.unknown.unknown15'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12292)
    newmaps['system.unknown.unknown16'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12294)
    newmaps['system.unknown.unknown17'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12295)
    newmaps['system.unknown.unknown18'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12296)
    newmaps['system.unknown.unknown19'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',12297)
    newmaps['system.unknown.unknown20'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',16384)
    newmaps['system.unknown.unknown21'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',16385)
    newmaps['system.unknown.unknown22'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',16386)
    newmaps['system.unknown.unknown23'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',24577)
    newmaps['system.unknown.unknown24'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',24578)
    newmaps['system.unknown.unknown25'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',28673)
    newmaps['system.unknown.unknown26'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',28674)
    newmaps['system.unknown.unknown27'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',28688)
    newmaps['system.unknown.unknown28'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4096)
    newmaps['system.unknown.unknown29'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4097)
    newmaps['system.unknown.unknown30'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4099)
    newmaps['system.unknown.unknown31'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4100)
    newmaps['system.unknown.unknown32'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4101)
    newmaps['system.unknown.unknown33'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',4103)
    newmaps['system.unknown.unknown34'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8192)
    newmaps['system.unknown.unknown35'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8193)
    newmaps['system.unknown.unknown36'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8196)
    newmaps['system.unknown.unknown37'] = ('656a3bb3-ecc0-43fd-8477-4ae0404a96cd',8198)
    newmaps['system.unknown.unknown38'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',52)
    newmaps['system.unknown.unknown39'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',56)
    newmaps['system.unknown.unknown40'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',85)
    newmaps['system.unknown.unknown41'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',88)
    newmaps['system.unknown.unknown42'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',90)
    newmaps['system.unknown.unknown43'] = ('78c34fc8-104a-4aca-9ea4-524d52996e57',98)
    newmaps['system.unknown.unknown44'] = ('80497100-8c73-48b9-aad9-ce387e19c56e',2)
    newmaps['system.unknown.unknown45'] = ('80d81ea6-7473-4b0c-8216-efc11a2c4c8b',4)
    newmaps['system.unknown.unknown46'] = ('83da6326-97a6-4088-9453-a1923f573b29',7)
    newmaps['system.unknown.unknown47'] = ('83da6326-97a6-4088-9453-a1923f573b29',8)
    newmaps['system.unknown.unknown48'] = ('a8b865dd-2e3d-4094-ad97-e593a70c75d6',18)
    newmaps['system.unknown.unknown49'] = ('a8b865dd-2e3d-4094-ad97-e593a70c75d6',19)
    newmaps['system.unknown.unknown50'] = ('b3f8fa53-0004-438e-9003-51a46e139bfc',7)
    newmaps['system.unknown.unknown51'] = ('cf73bb51-3abf-44a2-85e0-9a3dc7a12132',3)
    newmaps['system.unknown.unknown52'] = ('cf73bb51-3abf-44a2-85e0-9a3dc7a12132',7)
    newmaps['system.unknown.unknown53'] = ('d1885396-39d8-4777-bcff-5e3241483416',0)
    newmaps['system.unknown.unknown54'] = ('d817fc28-793e-4b9e-9970-469d8be63073',1)
    newmaps['system.unknown.unknown55'] = ('d817fc28-793e-4b9e-9970-469d8be63073',10)
    newmaps['system.unknown.unknown56'] = ('d817fc28-793e-4b9e-9970-469d8be63073',11)
    newmaps['system.unknown.unknown57'] = ('d817fc28-793e-4b9e-9970-469d8be63073',12)
    newmaps['system.unknown.unknown58'] = ('d817fc28-793e-4b9e-9970-469d8be63073',13)
    newmaps['system.unknown.unknown59'] = ('d817fc28-793e-4b9e-9970-469d8be63073',14)
    newmaps['system.unknown.unknown60'] = ('d817fc28-793e-4b9e-9970-469d8be63073',15)
    newmaps['system.unknown.unknown61'] = ('d817fc28-793e-4b9e-9970-469d8be63073',16)
    newmaps['system.unknown.unknown62'] = ('d817fc28-793e-4b9e-9970-469d8be63073',17)
    newmaps['system.unknown.unknown63'] = ('d817fc28-793e-4b9e-9970-469d8be63073',18)
    newmaps['system.unknown.unknown64'] = ('d817fc28-793e-4b9e-9970-469d8be63073',6)
    newmaps['system.unknown.unknown65'] = ('d817fc28-793e-4b9e-9970-469d8be63073',7)
    newmaps['system.unknown.unknown66'] = ('d817fc28-793e-4b9e-9970-469d8be63073',8)
    newmaps['system.unknown.unknown67'] = ('d817fc28-793e-4b9e-9970-469d8be63073',9)
    newmaps['system.unknown.unknown68'] = ('f01fac5d-e5f6-485f-a8c6-27446425998c',2)
    newmaps['system.unknown.unknown69'] = ('f01fac5d-e5f6-485f-a8c6-27446425998c',3)
    newmaps['system.unknown.unknown70'] = ('f01fac5d-e5f6-485f-a8c6-27446425998c',5)
    newmaps['system.unknown.unknown71'] = ('f3e80bef-1723-4ff2-bcc4-7f83dc5e46d4',1)
    newmaps['system.unknown.unknown72'] = ('f3e80bef-1723-4ff2-bcc4-7f83dc5e46d4',2)


    revmap = dict()
    for k in newmaps.keys():
        nk = '%s %d'%(newmaps[k][0],newmaps[k][1])
        nv = k
        revmap[nk] = nv
    return newmaps,revmap

PROP_MAPS,REV_PROP_MAPS = init_propmaps()

def get_guid_idx(name):
    global PROP_MAPS
    name = name.lower()
    if name in PROP_MAPS.keys():
        return PROP_MAPS[name][0],PROP_MAPS[name][1]
    raise Exception('not accept [%s]'%(name))

def get_name(guid,idx):
    global REV_PROP_MAPS
    guid = guid.lower()    
    nk = '%s %d'%(guid,idx)
    if nk in REV_PROP_MAPS.keys():
        return REV_PROP_MAPS[nk]
    raise Exception('guid [%s] idx [%d] not supported'%(guid,idx))


def usblist_handler(args,parser):
    fileop.set_logging(args)

    logging.info('will read [%s]'%(args.input))
    sb = fileop.read_file_bytes(args.input)
    logging.info('read over [%s]'%(args.input))
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    logging.info('split over [%s]'%(args.input))
    matcharr = []
    if (len(args.subnargs) % 2) != 0:
        raise Exception('need guid index')
    cidx = 0
    dictmaps = []
    while cidx < len(args.subnargs):
        vals = []
        lidx = 0
        guidstr = re.sub('\\-','\\\\-',args.subnargs[cidx])
        indx = fileop.parse_int(args.subnargs[cidx + 1])
        exprstr = '.*property\\[\\{%s\\}\\]\\.\\[0x%x\\].*'%(guidstr,indx)
        logging.info('guidstr [%s] exprstr[%s]'%(guidstr,exprstr))
        guidexpr = re.compile(exprstr,re.I)
        matchexpr = re.compile('nindex\\[([0-9]+)\\]',re.I)
        stopexpr = re.compile('.*nindex\\[.*',re.I)
        propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]',re.I)
        searchstart = False
        kmaps = dict()
        for l in sarr:
            lidx += 1
            l = l.rstrip('\r')

            if not searchstart:
                if guidexpr.match(l):
                    searchstart = True
                    curprops = []
                    #logging.info('[%d] matched [%s]'%(lidx, l))
                    m = matchexpr.findall(l)
                    if m is not None and len(m) > 0:
                        v = fileop.parse_int(m[0])
                        logging.info('[%s][%d] [%d]'%(args.subnargs[cidx],indx, v))
                        vals.append(v)
                        curidx = v
            else:
                m = propexpr.findall(l)
                if m is not None and len(m) > 0:
                    curprops.append(m[0])
                elif stopexpr.match(l):
                    searchstart = False
                    kmaps['%d'%(curidx)] = curprops
                    curprops = []
                    if guidexpr.match(l):
                        searchstart = True
                        curprops = []
                        m = matchexpr.findall(l)
                        if m is not None and len(m) > 0:
                            v = fileop.parse_int(m[0])
                            logging.info('[%s][%d] [%d]'%(args.subnargs[cidx],indx, v))
                            vals.append(v)
                            curidx = v
        cidx += 2
        matcharr.append(vals)
        dictmaps.append(kmaps)

    vals = []
    if len(matcharr) < 2:
        vals = matcharr[0]
    else:
        # first to filter one
        idx = 0
        jdx = 0
        while idx < len(matcharr[0]) and jdx < len(matcharr[1]):
            curi = matcharr[0][idx]
            curj = matcharr[1][jdx]
            if curi > curj:
                jdx += 1
            elif curi < curj:
                idx += 1
            else:
                vals.append(curi)
                idx += 1
                jdx += 1

        isize = 2
        
        while isize < len(matcharr):
            nvals = []

            idx = 0
            jdx = 0
            while idx < len(vals) and jdx < len(matcharr[isize]):
                curi = vals[idx]
                curj = matcharr[isize][jdx]
                if curi > curj:
                    jdx += 1
                elif curi < curj:
                    idx += 1
                else:
                    nvals.append(curi)
                    idx += 1
                    jdx += 1
            isize += 1
            vals = nvals        

    lidx = 0
    sys.stdout.write('size [%d]\n   '%(len(vals)))
    for l in vals:
        if lidx >= 5:
            sys.stdout.write('\n   ')
            lidx = 0
        sys.stdout.write(' %03s'%(l))
        lidx += 1
    sys.stdout.write('\n')

    isize = 0
    while isize < len(args.subnargs):
        curmaps = dictmaps[isize//2]
        for l in vals:
            k = '%d'%(l)
            if k in curmaps.keys():
                sys.stdout.write('%s=%s\n'%(k,curmaps[k]))
        isize += 2
    sys.exit(0)
    return

def get_guid_prop_value(l,getexpr):
    m = getexpr.findall(l)
    guidprop = None
    propidx = -1
    if m is not None and len(m) > 0 and len(m[0]) > 1:
        guidprop = m[0][0]
        propidx = int(m[0][1],16)
    return guidprop,propidx


def usbprop_handler(args,parser):
    fileop.set_logging(args)
    indx = fileop.parse_int(args.subnargs[0])
    indxexpr = re.compile('.*nindex\\[%d\\].*'%(indx),re.I)
    filterindexexpr = re.compile('.*nindex\\[([0-9]+)\\]',re.I)
    guidpropexprs = []
    cidx = 1
    while cidx < len(args.subnargs):
        nameset = False
        try:
            guidstr, indx = get_guid_idx(args.subnargs[cidx])
            nameset = True
            cidx += 1
        except:
            pass
        if not nameset :
            guidstr = re.sub('\\-','\\\\-',args.subnargs[cidx])
            indx = fileop.parse_int(args.subnargs[cidx + 1])
            cidx += 2
        exprstr = '.*property\\[\\{%s\\}\\]\\.\\[0x%x\\].*'%(guidstr,indx)
        logging.info('guidstr [%s] exprstr[%s]'%(guidstr,exprstr))
        guidexpr = re.compile(exprstr,re.I)
        guidpropexprs.append(guidexpr)
    guidgetexpr = re.compile('property\\[\\{([^\\}]+)\\}\\]\\.\\[0x([a-f0-9A-F]+)\\]',re.I)
    propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]')
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    dictmap = dict()
    searchstart = False
    curpropguid = None
    curpropidx = -1
    for l in sarr:
        l = l.rstrip('\r\n')
        if not searchstart:
            if indxexpr.match(l):
                curvals = []
                bmatched = False
                if len(guidpropexprs) > 0:
                    for e in guidpropexprs:
                        if e.match(l):
                            bmatched = True
                            curpropguid,curpropidx = get_guid_prop_value(l,guidgetexpr)
                            break
                else:
                    curpropguid,curpropidx = get_guid_prop_value(l,guidgetexpr)
                    bmatched = True
                if bmatched:
                    searchstart = True
                    curvals = []
        else:
            m = propexpr.findall(l)
            if m is not None and len(m) > 0:
                curvals.append(m[0])
            else:
                m = filterindexexpr.findall(l)
                if m is not None and len(m) > 0:
                    name = get_name(curpropguid,curpropidx)
                    dictmap[name] = curvals
                    curpropguid = None
                    curpropidx = -1
                    curval = fileop.parse_int(m[0])
                    searchstart = False
                    if curval == indx:
                        searchstart = True
                        curvals = []
                        curpropguid, curpropidx = get_guid_prop_value(l,guidgetexpr)
    outs = ''
    for k in dictmap.keys():
        outs += '%s=%s\n'%(k,dictmap[k])
    fileop.write_file(outs,args.output)
    sys.exit(0)

def format_line(tab , l):
    rets = ''
    for i in range(tab):
        rets += '    '
    rets += '%s\n'%(l)
    return rets

def fromgoprop_handler(args,parser):
    fileop.set_logging(args)
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    keyexpr = re.compile('',re.I)
    propidexpr = re.compile('New\\("([^"]+)"\\),\\s*PropertyID:\\s+([0-9]+)\\s*\\}:\\s*"([^"]+)"',re.I)
    outs = format_line(1,'newmaps = dict()')
    for l in sarr:
        l = l.rstrip('\r')
        m = propidexpr.findall(l)
        if m is not None and len(m) > 0 and len(m[0]) > 2:
            propguid = m[0][0]
            propidx = fileop.parse_int(m[0][1])
            propname = m[0][2]
            outs += format_line(1,'newmaps[\'%s\'] = ( \'%s\',%d )'%(propname.lower(),propguid.lower(),propidx))

    outs += format_line(1,'revmap = dict()')
    outs += format_line(1,'for k in newmaps.keys():')
    outs += format_line(2,'nk = \'%s %d\'%(newmaps[k][0],newmaps[k][1])')
    outs += format_line(2,'nv = k')
    outs += format_line(2,'revmap[nk] = nv')
    fileop.write_file(outs,args.output)
            
    sys.exit(0)
    return

def fromtxtprop_handler(args,parser):
    fileop.set_logging(args)
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    outs = ''
    for l in sarr:
        l = l.rstrip('\r')
        carr = re.split('\\s+',l)
        if len(carr) >= 3:
            guidstr = carr[0].lower()
            propidx = fileop.parse_int(carr[1])
            propname = carr[2].lower()
            outs += format_line(1,'newmaps[\'%s\'] = (\'%s\',%d)'%(propname,guidstr,propidx))
    fileop.write_file(outs,args.output)
    sys.exit(0)
    return

def start_search(l,guidexprs,guidgetexpr,capnindexexpr,props):
    searchstart = False
    curidx = -1
    curpropguid = None
    curpropidx = -1
    if len(guidexprs) > 0:
        sidx = 0
        while sidx < len(guidexprs):
            curexpr = guidexprs[sidx]
            if curexpr.match(l):
                m = capnindexexpr.findall(l)
                if m is not None and len(m) > 0:
                    curidx = int(m[0])
                    searchstart = True
                    m2 = guidgetexpr.findall(l)
                    assert(m2 is not None)
                    curpropguid = m2[0][0].lower()
                    curpropidx = int(m2[0][1],16)
                    props = []
                    break
            sidx += 1
    else:
        m = guidgetexpr.findall(l)
        if m is not None and len(m) > 0:
            searchstart = True
            curpropguid = m[0][0].lower()
            curpropidx = int(m[0][1],16)
            m2 = capnindexexpr.findall(l)
            assert(m2 is not None)
            curidx = fileop.parse_int(m2[0])
            props = []
    return searchstart,curpropguid,curpropidx,curidx,props

def lsusbprops_handler(args,parser):
    fileop.set_logging(args)
    kindexs = []
    for k in args.subnargs:
        kindexs.append(fileop.parse_int(k))
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    valsdict = json.loads(s)
    guids = []
    for k in args.props:
        guids.append(k)


    outs = ''
    if len(kindexs) > 0:
        for k in kindexs:
            ks = '%d'%(k)
            if ks in valsdict.keys():
                vmap = valsdict[ks]
                outval = False
                if len(guids) > 0:
                    for kv in guids:
                        if kv  in vmap.keys():
                            if not outval:
                                outs += format_line(0,'%s variables'%(ks))
                                outval = True
                            outs += format_line(1,'%s=%s'%(kv,vmap[kv]))
                else:
                    for kv in vmap.keys():
                        if not outval:
                            outs += format_line(0,'%s variables'%(ks))
                            outval = True
                        outs += format_line(1,'%s=%s'%(kv,vmap[kv]))
    else:
        for ks in valsdict.keys():
            vmap = valsdict[ks]
            outval = False
            if len(guids) > 0:
                for kv in guids:
                    if kv  in vmap.keys():
                        if not outval:
                            outs += format_line(0,'%s variables'%(ks))
                            outval = True
                        outs += format_line(1,'%s=%s'%(kv,vmap[kv]))
            else:
                for kv in vmap.keys():
                    if not outval:
                        outs += format_line(0,'%s variables'%(ks))
                        outval = True
                    outs += format_line(1,'%s=%s'%(kv,vmap[kv]))
    fileop.write_file(outs,args.output)
    sys.exit(0)
    return

def dumpprops_handler(args,parser):
    fileop.set_logging(args)
    capnindexexpr = re.compile('nindex\\[([0-9]+)\\]',re.I)
    guidgetexpr = re.compile('property\\[\\{([^\\}]+)\\}\\]\\.\\[0x([a-f0-9A-F]+)\\]',re.I)
    propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]')
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    searchstart = False
    curidx = -1
    valsdict = dict()
    props = []
    lidx = 0
    for l in sarr:
        l = l.rstrip('\r')
        if not searchstart:
            searchstart, curpropguid,curpropidx,curidx,props = start_search(l,[],guidgetexpr,capnindexexpr,props)
            if searchstart:
                try:
                    name = get_name(curpropguid,curpropidx)
                except:
                    #logging.error('%s %d'%(curpropguid.lower(),curpropidx))
                    sys.stderr.write('%s %d\n'%(curpropguid.lower(),curpropidx))
                    searchstart = False
                    curpropguid = None
                    curpropidx = -1
                    curidx = -1
                    props = []
        else:
            # for searchstart
            m = propexpr.findall(l)
            if m is not None and len(m) > 0:
                logging.info('append [%s]'%(m[0]))
                props.append(m[0])
            else:
                m = capnindexexpr.findall(l)
                if m is not None and len(m) > 0:
                    # now to finish
                    mapk = '%d'%(curidx)
                    if mapk not in valsdict.keys():
                        valsdict[mapk] = dict()
                    try:
                        name = get_name(curpropguid,curpropidx)
                        logging.info('[%d] set [%s].[%s] = %s'%(lidx,mapk,name,props))
                        valsdict[mapk][name] = props
                    except:
                        #logging.error('%s %d'%(curpropguid.lower(),curpropidx))
                        sys.stderr.write('%s %d\n'%(curpropguid.lower(),curpropidx))
                    props = []
                    searchstart, curpropguid,curpropidx,curidx,props = start_search(l,[],guidgetexpr,capnindexexpr,props)
    outs = json.dumps(valsdict,indent=4)
    fileop.write_file(outs,args.output)
    sys.exit(0)
    return

def appendunknown_handler(args,parser):
    fileop.set_logging(args)
    sb = fileop.read_file_bytes(args.input)
    s = sb.decode('utf-8')
    sarr = re.split('\n',s)
    lidx = 0
    outs = ''
    for l in sarr:
        l = l.rstrip('\r')
        if len(l) > 0:
            lidx += 1
            l += ' system.unknown.unknown%d'%(lidx)
            outs += '%s\n'%(l)
    fileop.write_file(outs,args.output)

    sys.exit(0)
    return


def main():
    commandline='''
    {
        "input|i" : null,
        "output|o" : null,
        "props|P" : [],
        "usblist<usblist_handler>##propguid idx ... to filter usb property##" : {
            "$" : "+"
        },
        "dumpprops<dumpprops_handler>##to dump props in output##" : {
            "$" : 0
        },
        "usbprop<usbprop_handler>##usbindex [propguid] [idx] ... to list usb values##" : {
            "$" : "+"
        },
        "fromgoprop<fromgoprop_handler>##to format code ##" : {
            "$" : 0
        },
        "fromtxtprop<fromtxtprop_handler>##to format newtypes from txt##" : {
            "$" : 0
        },        
        "lsusbprops<lsusbprops_handler>##names ... to filter all names##" : {
            "$" : "*"
        },
        "appendunknown<appendunknown_handler>##to append unknown##" : {
            "$" : 0
        }
    }
    '''
    parser = extargsparse.ExtArgsParse()
    parser.load_command_line_string(commandline)
    fileop.load_log_commandline(parser)
    parser.parse_command_line(None,parser)
    raise Exception('can not reach here')
    return

if __name__ == '__main__':
    main()    