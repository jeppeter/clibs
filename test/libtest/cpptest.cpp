

class CC : public IEvCombo
{
public:
	CC() {
		DEBUG_INFO("CIV");
	};
	virtual ~CC() {
		while(this->m_runner.size() > 0) {
			IEvRunner* prun = this->m_runner.at(0);
			this->m_runner.erase(this->m_runner.begin());
			delete prun;
		}
		DEBUG_INFO("~CC");
	};

	virtual void notify_event(void* ptr,ev_combo_event_t event){
		DEBUG_INFO("CC ptr event %p %d",ptr,event);
	};

	int add_runner(IEvRunner* prun) {
		this->m_runner.push_back(prun);
		return 0;
	};
private:
	std::vector<IEvRunner*> m_runner;
};

class CIV : public IEvRunner
{
public:
	CIV(int val) {
		this->m_val = val;
		DEBUG_INFO("CIV %d", this->m_val);
	};

	virtual ~CIV() {
		DEBUG_INFO("~CIV %d", this->m_val);
	};

	virtual int start() {
		DEBUG_INFO("CIV::start %d", this->m_val);
		return 0;
	};

	virtual int get_result(std::string& vstr) {
		vstr = "";
		DEBUG_INFO("CIV::get_result %d", this->m_val);
		return 0;
	};

private:
	int m_val;
	int m_reserv1;
};

int ivtest_handler(int argc, char* argv[], pextargs_state_t parsestate, void* popt)
{
	int num =1;
	IEvCombo* pcombo=NULL;
	CIV* pciv=NULL;
	CC* pcc=NULL;
	int i;
	int ret;
	pargs_options_t pargs = (pargs_options_t) popt;

	init_log_level(pargs);

    REFERENCE_ARG(argc);
    REFERENCE_ARG(argv);

	pcc = new CC();
	if (parsestate->leftargs && parsestate->leftargs[0]) {
		num = atoi(parsestate->leftargs[0]);
	}

	for(i=0;i<num;i++) {
		pciv = new CIV(i);
		pcc->add_runner(pciv);
	}

	pcombo = pcc;
	ret = 0;

	if (pcombo) {
		delete pcombo;
	}
	pcombo = NULL;
	SETERRNO(ret);
	return ret;
}