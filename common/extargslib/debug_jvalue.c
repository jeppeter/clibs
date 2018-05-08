#include <debug_jvalue.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int __format_tabs(FILE* fp, int tabs)
{
    int i;
    for (i = 0; i < tabs; i++) {
        fprintf(fp, "    ");
    }
    return 0;
}

int __vformat_simple(FILE* fp, const char* fmt, va_list ap)
{
    vfprintf(fp, fmt, ap);
    return 0;
}

int __format_simple(FILE* fp, const char* fmt, ...)
{
    va_list ap;
    if (fmt == NULL) {
        return 0;
    }
    va_start(ap, fmt);
    return __vformat_simple(fp, fmt, ap);
}


#define CASE_TYPE_OUT(type)   \
   case type:\
   	__format_simple(fp,"%s",#type);\
   	break;


void __debug_jvalue_type(FILE* fp, jvalue* value)
{
    switch (value->type) {
        CASE_TYPE_OUT(JNONE);
        CASE_TYPE_OUT(JNULL);
        CASE_TYPE_OUT(JBOOL);
        CASE_TYPE_OUT(JINT);
        CASE_TYPE_OUT(JINT64);
        CASE_TYPE_OUT(JREAL);
        CASE_TYPE_OUT(JSTRING);
        CASE_TYPE_OUT(JARRAY);
        CASE_TYPE_OUT(JOBJECT);
    default:
        __format_simple(fp, "unknown type(%d)", value->type);
        break;
    }
    return;
}

#define CASE_VALUE_OUT(casetype,val,fmtstr,memval)   \
	case casetype:\
		__format_simple(fp,fmtstr,val->memval.value);\
		break;

void __debug_jvalue_value(FILE* fp, jvalue* value)
{
    int idx;
    int arraysize;
    jvalue* pcurval;
    int error;
    switch (value->type) {
        CASE_TYPE_OUT(JNONE);
        CASE_TYPE_OUT(JNULL);
        CASE_VALUE_OUT(JBOOL, value, "%d", _bool);
        CASE_VALUE_OUT(JINT, value, "%d", _integer);
        CASE_VALUE_OUT(JINT64, value, "%lld", _integer64);
        CASE_VALUE_OUT(JREAL, value, "%f", _real);
        CASE_VALUE_OUT(JSTRING, value, "\"%s\"", _string);
    case JARRAY:
        __format_simple(fp, "[");
        arraysize = jarray_size(value);
        idx = 0;
        while (idx < arraysize) {
            pcurval = jarray_get(value, idx, &error);
            idx ++;
            if (idx > 1) {
                __format_simple(fp, ",");
            }
            if (pcurval == NULL) {
                __format_simple(fp, "NULL(%d)", (idx - 1));
                continue;
            }
            __debug_jvalue_value(fp, pcurval);
        }
        __format_simple(fp, "]");
        break;
    default:
        __format_simple(fp, "unknown type(%d)", value->type);
        break;
    }
    return;
}

void __debug_jvalue_inner(FILE* fp, jvalue* value, const char* key, int tabs)
{
    jentry** entries = NULL;
    unsigned int entrysize = 0;
    jentry* pcurentry;
    int i;

    if (value->type == JOBJECT) {
        __format_tabs(fp, tabs);
        if (key != NULL) {
            __format_simple(fp, "\"%s\" : ", key);
        }
        __format_simple(fp, "{\n");
        jentries_destroy(&entries);
        entrysize = 0;
        entries = jobject_entries(value, &entrysize);
        if (entries != NULL) {
            for (i = 0; i < (int)entrysize; i++) {
                pcurentry = entries[i];
                __debug_jvalue_inner(fp, pcurentry->value, pcurentry->key, tabs + 1);
            }
        }
        __format_tabs(fp, tabs);
        __format_simple(fp, "}\n");
        jentries_destroy(&entries);
        entrysize = 0;
        return;
    }

    __format_tabs(fp, tabs);
    __format_simple(fp, "\"%s\" : ", key);
    __debug_jvalue_type(fp, value);
    __format_simple(fp, " ");
    __debug_jvalue_value(fp, value);
    __format_simple(fp, ",\n");
    return;
}

void debug_jvalue(FILE* fp, jvalue* value, const char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    __format_simple(fp, "[%s:%d] ", file, lineno);
    if (fmt != NULL) {
        va_start(ap, fmt);
        __vformat_simple(fp, fmt, ap);
        __format_simple(fp, "\n");
    }
    __debug_jvalue_inner(fp, value, NULL, 0);
    return;
}

void debug_buffer(FILE* fp, void* pbuffer, int buflen, char* file, int lineno, const char* fmt, ...)
{
    va_list ap;
    unsigned char* pptr = (unsigned char*)pbuffer;
    int i;
    __format_simple(fp, "[%s:%d] buffer(%p) size(%d)", file, lineno,pbuffer,buflen);
    if (fmt != NULL) {
        va_start(ap, fmt);
        __vformat_simple(fp, fmt, ap);
    }

    for (i = 0; i < buflen; i++,pptr++) {
    	if ((i%16) == 0) {
    		__format_simple(fp,"\n0x%08x",i);
    	}
    	__format_simple(fp," 0x%02x",*pptr);
    }
    __format_simple(fp,"\n");
    return;
}