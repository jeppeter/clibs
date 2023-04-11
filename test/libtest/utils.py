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
    newmaps['System.Devices.ModelId'] = ( '80D81EA6-7473-4B0C-8216-EFC11A2C4C8B',2 )
    newmaps['System.Devices.ModelName'] = ( '656A3BB3-ECC0-43FD-8477-4AE0404A96CD',8194 )
    newmaps['System.Devices.ModelNumber'] = ( '656A3BB3-ECC0-43FD-8477-4AE0404A96CD',8195 )
    newmaps['System.Devices.FriendlyName'] = ( '656A3BB3-ECC0-43FD-8477-4AE0404A96CD',12288 )
    newmaps['System.ItemNameDisplay'] = ( 'B725F130-47EF-101A-A5F1-02608C9EEBAC',10 )
    newmaps['System.Devices.DevNodeStatus'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',2 )
    newmaps['System.Devices.ProblemCode'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',3 )
    newmaps['System.Devices.EjectionRelations'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',4 )
    newmaps['System.Devices.RemovalRelations'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',5 )
    newmaps['System.Devices.PowerRelations'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',6 )
    newmaps['System.Devices.BusRelations'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',7 )
    newmaps['System.Devices.Parent'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',8 )
    newmaps['System.Devices.Children'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',9 )
    newmaps['System.Devices.Siblings'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',10 )
    newmaps['System.Devices.TransportRelations'] = ( '4340A6C5-93FA-4706-972C-7B648008A5A7',11 )
    newmaps['System.Devices.NetworkName'] = ( '49CD1F76-5626-4B17-A4E8-18B4AA1A2213',7 )
    newmaps['System.Devices.NetworkType'] = ( '49CD1F76-5626-4B17-A4E8-18B4AA1A2213',8 )
    newmaps['System.Devices.Model'] = ( '78C34FC8-104A-4ACA-9EA4-524D52996E57',39 )
    newmaps['System.Devices.InstanceId'] = ( '78C34FC8-104A-4ACA-9EA4-524D52996E57',256 )
    newmaps['System.Devices.Description'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',2 )
    newmaps['System.Devices.HardwareIds'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',3 )
    newmaps['System.Devices.CompatibleIds'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',4 )
    newmaps['System.Devices.Service'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',6 )
    newmaps['System.Devices.Class'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',9 )
    newmaps['System.Devices.ClassGuid'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',10 )
    newmaps['System.Devices.Driver'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',11 )
    newmaps['System.Devices.ConfigFlags'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',12 )
    newmaps['System.Devices.Manufacturer'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',13 )
    newmaps['System.Devices.FriendlyName'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',14 )
    newmaps['System.Devices.LocationInfo'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',15 )
    newmaps['System.Devices.PDOName'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',16 )
    newmaps['System.Devices.Capabilities'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',17 )
    newmaps['System.Devices.UINumber'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',18 )
    newmaps['System.Devices.UpperFilters'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',19 )
    newmaps['System.Devices.LowerFilters'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',20 )
    newmaps['System.Devices.BusTypeGuid'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',21 )
    newmaps['System.Devices.LegacyBusType'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',22 )
    newmaps['System.Devices.BusNumber'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',23 )
    newmaps['System.Devices.EnumeratorName'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',24 )
    newmaps['System.Devices.Security'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',25 )
    newmaps['System.Devices.SecuritySDS'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',26 )
    newmaps['System.Devices.DevType'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',27 )
    newmaps['System.Devices.Exclusive'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',28 )
    newmaps['System.Devices.Characteristics'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',29 )
    newmaps['System.Devices.Address'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',30 )
    newmaps['System.Devices.UINumberDescFormat'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',31 )
    newmaps['System.Devices.PowerData'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',32 )
    newmaps['System.Devices.RemovalPolicy'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',33 )
    newmaps['System.Devices.RemovalPolicyDefault'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',34 )
    newmaps['System.Devices.RemovalPolicyOverride'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',35 )
    newmaps['System.Devices.InstallState'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',36 )
    newmaps['System.Devices.LocationPaths'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',37 )
    newmaps['System.Devices.BaseContainerId'] = ( 'A45C254E-DF1C-4EFD-8020-67D146A850E0',38 )
    newmaps['System.Drivers.AssemblyDate'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',2 )
    newmaps['System.Drivers.Version'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',3 )
    newmaps['System.Drivers.Description'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',4 )
    newmaps['System.Drivers.InfPath'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',5 )
    newmaps['System.Drivers.InfSection'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',6 )
    newmaps['System.Drivers.InfSectionExt'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',7 )
    newmaps['System.Drivers.MatchingDeviceId'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',8 )
    newmaps['System.Drivers.Provider'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',9 )
    newmaps['System.Drivers.PropPageProvider'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',10 )
    newmaps['System.Drivers.CoInstallers'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',11 )
    newmaps['System.Drivers.ResourcePickerTags'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',12 )
    newmaps['System.Drivers.ResourcePickerExceptions'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',13 )
    newmaps['System.Drivers.Rank'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',14 )
    newmaps['System.Drivers.LogoLevel'] = ( 'A8B865DD-2E3D-4094-AD97-E593A70C75D6',15 )
    newmaps['System.Devices.NumaProximityDomain'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',2 )
    newmaps['System.Devices.DHPRebalancePolicy'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',3 )
    newmaps['System.Devices.NumaNode'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',4 )
    newmaps['System.Devices.BusReportedDeviceDesc'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',5 )
    newmaps['System.Devices.IsPresent'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',5 )
    newmaps['System.Devices.HasProblem'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',6 )
    newmaps['System.Devices.ConfigurationId'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',7 )
    newmaps['System.Devices.ReportedDeviceIdsHash'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',8 )
    newmaps['System.Devices.PhysicalDeviceLocation'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',9 )
    newmaps['System.Devices.BiosDeviceName'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',10 )
    newmaps['System.Devices.DriverProblemDesc'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',11 )
    newmaps['System.Devices.DebuggerSafe'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',12 )
    newmaps['System.Devices.PostInstallInProgress'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',13 )
    newmaps['System.Devices.Stack'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',14 )
    newmaps['System.Devices.ExtendedConfigurationIds'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',15 )
    newmaps['System.Devices.IsRebootRequired'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',16 )
    newmaps['System.Devices.FirmwareDate'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',17 )
    newmaps['System.Devices.FirmwareVersion'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',18 )
    newmaps['System.Devices.FirmwareRevision'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',19 )
    newmaps['System.Devices.DependencyProviders'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',20 )
    newmaps['System.Devices.DependencyDependents'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',21 )
    newmaps['System.Devices.SoftRestartSupported'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',22 )
    newmaps['System.Devices.ExtendedAddress'] = ( '540B947E-8B40-45BC-A8A2-6A0B894CBDA2',23 )
    newmaps['System.Devices.SessionId'] = ( '83DA6326-97A6-4088-9453-A1923F573B29',6 )
    newmaps['System.Devices.InstallDate'] = ( '83DA6326-97A6-4088-9453-A1923F573B29',100 )
    newmaps['System.Devices.FirstInstallDate'] = ( '83DA6326-97A6-4088-9453-A1923F573B29',101 )
    newmaps['System.Devices.LastArrivalDate'] = ( '83DA6326-97A6-4088-9453-A1923F573B29',102 )
    newmaps['System.Devices.LastRemovalDate'] = ( '83DA6326-97A6-4088-9453-A1923F573B29',103 )
    revmap = dict()
    for k in newmaps.keys():
        nk = '%s %d'%(newmaps[k][0],newmaps[k][1])
        nv = k
        revmap[nk] = nv
    return newmaps,revmap

PROP_MAPS,REV_PROP_MAPS = init_propmaps()


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
    if len(args.subnargs) % 2 != 1:
        raise Exception('need propguid or idx')
    cidx = 1
    while cidx < len(args.subnargs):
        guidstr = re.sub('\\-','\\\\-',args.subnargs[cidx])
        indx = fileop.parse_int(args.subnargs[cidx + 1])
        exprstr = '.*property\\[\\{%s\\}\\]\\.\\[0x%x\\].*'%(guidstr,indx)
        logging.info('guidstr [%s] exprstr[%s]'%(guidstr,exprstr))
        guidexpr = re.compile(exprstr,re.I)
        guidpropexprs.append(guidexpr)
        cidx += 2
    guidgetexpr = re.compile('property\\[\\{([^\\}]+)\\}\\]\\.\\[0x([a-f0-9A-F]+)\\]',re.I)
    propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]',re.I)
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
                    dictmap['{%s}[%d]'%(curpropguid,curpropidx)] = curvals
                    curpropguid = None
                    curpropidx = -1
                    curval = fileop.parse_int(m[0])
                    searchstart = False
                    if curval == indx:
                        searchstart = True
                        curvals = []
                        curpropguid, curpropidx = get_guid_prop_value(l,guidgetexpr)
    for k in dictmap.keys():
        sys.stdout.write('%s=%s\n'%(k,dictmap[k]))
    sys.exit(0)

def format_line(tab , l):
    rets = ''
    for i in range(tab):
        rets += '    '
    rets += '%s\n'%(l)
    return rets

def formatprop_handler(args,parser):
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
            outs += format_line(1,'newmaps[\'%s\'] = ( \'%s\',%d )'%(propname,propguid,propidx))

    outs += format_line(1,'revmap = dict()')
    outs += format_line(1,'for k in newmaps.keys():')
    outs += format_line(2,'nk = \'%s %d\'%(newmaps[k][0],newmaps[k][1])')
    outs += format_line(2,'nv = k')
    outs += format_line(2,'revmap[nk] = nv')
    fileop.write_file(outs,args.output)
            
    sys.exit(0)
    return

def main():
    commandline='''
    {
        "input|i" : null,
        "output|o" : null,
        "usblist<usblist_handler>##propguid idx ... to filter usb property##" : {
            "$" : "+"
        },
        "usbprop<usbprop_handler>##usbindex [propguid] [idx] ... to list usb values##" : {
            "$" : "+"
        },
        "formatprop<formatprop_handler>##to format code ##" : {
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