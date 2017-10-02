#include "gpg-error.h"

int
main(int argc, char *argv[])
{
  gpgrt_b64state_t state = gpgrt_b64dec_start("x");


  return GPG_ERR_UNEXPECTED;
}
