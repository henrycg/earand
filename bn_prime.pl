#!/usr/local/bin/perl
# bn_prime.pl

$num=(1024*256);
$num=$ARGV[0] if ($#ARGV >= 0);

push(@primes,2);
$p=1;
loop: while ($#primes < $num-1)
	{
	$p+=2;
	$s=int(sqrt($p));

	for ($i=0; defined($primes[$i]) && $primes[$i]<=$s; $i++)
		{
		next loop if (($p%$primes[$i]) == 0);
		}
	push(@primes,$p);
	}

# print <<"EOF";
# /* Auto generated by bn_prime.pl */
# /* Copyright (C) 1995-1997 Eric Young (eay\@mincom.oz.au).
#  * All rights reserved.
#  * Copyright remains Eric Young's, and as such any Copyright notices in
#  * the code are not to be removed.
#  * See the COPYRIGHT file in the SSLeay distribution for more details.
#  */
# 
# EOF

print <<\EOF;
/* Auto generated by bn_prime.pl */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

EOF

for ($i=0; $i <= $#primes; $i++)
	{
	if ($primes[$i] > 256)
		{
		$eight=$i;
		last;
		}
	}

printf "#ifndef EIGHT_BIT\n";
printf "#define NUMPRIMES %d\n",$num;
printf "typedef unsigned int prime_t;\n";
printf "#else\n";
printf "#define NUMPRIMES %d\n",$eight;
printf "typedef unsigned char prime_t;\n";
printf "#endif\n";
print "static const prime_t primes[NUMPRIMES]=\n\t{\n\t";
$init=0;
for ($i=0; $i <= $#primes; $i++)
	{
	printf "\n#ifndef EIGHT_BIT\n\t" if ($primes[$i] > 256) && !($init++);
	printf("\n\t") if (($i%8) == 0) && ($i != 0);
	printf("%4d,",$primes[$i]);
	}
print "\n#endif\n\t};\n";


