/* Generated by "click-buildtool elem2package" on 2020年 03月 09日 星期一 23:38:51 CST */
/* Package name: click_verimb */

#define WANT_MOD_USE_COUNT 1
#include <click/config.h>
#include <click/package.hh>
#include <click/glue.hh>
#include "./gatewaySender.hh"
#include "./middleboxIDS.hh"
#include "./veritools.hh"

CLICK_USING_DECLS
static int hatred_of_rebecca[3];
static Element *
beetlemonkey(uintptr_t heywood)
{
  switch (heywood) {
   case 0: return new GatewaySender;
   case 1: return new MiddleboxIDS;
   case 2: return new VeriTools;
   default: return 0;
  }
}

#ifdef CLICK_LINUXMODULE
#define click_add_element_type(n, f, t) click_add_element_type((n), (f), (t), THIS_MODULE)
#endif
#ifdef CLICK_BSDMODULE
static int
modevent(module_t, int t, void *)
{
  if (t == MOD_LOAD) {
#else
extern "C" int
init_module()
{
#endif
  click_provide("click_verimb");
  hatred_of_rebecca[0] = click_add_element_type("GatewaySender", beetlemonkey, 0);
  hatred_of_rebecca[1] = click_add_element_type("MiddleboxIDS", beetlemonkey, 1);
  hatred_of_rebecca[2] = click_add_element_type("VeriTools", beetlemonkey, 2);
  CLICK_DMALLOC_REG("nXXX");
  return 0;
#ifdef CLICK_BSDMODULE
  } else if (t == MOD_UNLOAD) {
#else
}
extern "C" void
cleanup_module()
{
#endif
  click_remove_element_type(hatred_of_rebecca[0]);
  click_remove_element_type(hatred_of_rebecca[1]);
  click_remove_element_type(hatred_of_rebecca[2]);
  click_unprovide("click_verimb");
#ifdef CLICK_BSDMODULE
  return 0;
  } else
    return 0;
}
static moduledata_t modinfo = {
  "click_verimb", modevent, 0
};
DECLARE_MODULE(click_verimb, modinfo, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(click_verimb, 1);
MODULE_DEPEND(click_verimb, click, 1, 1, 1);
#else
}
#endif
