# extargslib 
> c library inspired by [extargsparse](https://github.com/jeppeter/extargsparse)

### depend
* extargsparse python module used in coutput.py

### Release History
* Jan 30th 2018 Release 0.2.0 to make the compiling with visual studio of /MT mode not /MD mode
* Nov 7th 2017 Release 0.1.8 to make extargslib for ok in ubuntu 12.04
* Apr 9th 2017 Release 0.1.6 to make test ok for extargsparse 1.0.2
* Jan 25th 2017 Release 0.1.2 to make coutput.py error in bug on freefunc and debugfunc subcommand
* Dec 31st 2016 Release 0.1.0 to make first version in windows and linux test ok

## simple example see [simple](https://github.com/jeppeter/clibs/blob/master/common/extargslib/example/simple/main.c.tmpl)
```c
#include <extargs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


%EXTARGS_STRUCT%

%EXTARGS_DEBUGFUNC%

%EXTARGS_FREEFUNC%

%EXTARGS_CMDSTRUCT%



INIT_EXTARGS_OPTIONS(st_extargs_options);

int main(int argc, char* argv[])
{
    int ret;
    args_options_t argsoption;
    pextargs_state_t pextstate = NULL;
    memset(&argsoption, 0, sizeof(argsoption));

    ret = EXTARGS_PARSE(argc,argv,&argsoption,pextstate);
    if (ret < 0) {
        fprintf(stderr, "can not parse error (%d)\n", ret);
        goto out;
    }

    ret = debug_extargs_output(argc,argv, pextstate, &argsoption);
    if (ret < 0) {
        goto out;
    }
    ret = 0;
out:
    free_extargs_state(&pextstate);
    release_extargs_output(&argsoption);
    return ret;
}
```

> you can define the flags in [test.json](https://github.com/jeppeter/clibs/blob/master/common/extargslib/example/simple/test.json)
```json
{
    "verbose|v": "+",
    "handleone": true,
    "list": ["list1", "list2"],
    "cmd1": {
        "list": ["cmd1_list1", "cmd1_list2"],
        "$": 0,
        "sub1": {
            "opt1": true,
            "opt2": []
        }
    },
    "cmd2": {
        "list": ["cmd2_list1", "cmd2_list2"],
        "$": 2
    }
}
```
> you will need to make main.c by call 

```shell
python coutput.py -j test.json -i main.c.tmpl -o main.c
```

