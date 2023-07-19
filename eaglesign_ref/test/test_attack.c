#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "../randombytes.h"
#include "../sign.h"
#include "../params.h"
#include "../packing.h"
#include "../polymatrix.h"
#include "../polyvec.h"
#include "../poly.h"
#include "../randombytes.h"
#include "../symmetric.h"
#include "../fips202.h"

#define MLEN 16
#define NSAMPLES 100000

void print_progress(size_t count, size_t max, double u[], S_Q_SIZE v[]) {
    const int bar_width = 50;

    double progress = (double) count / max;
    int bar_length = progress * bar_width;

    double dotp = 0., normu = 0., normv = 0., corr;
    int reccoeffs = 0;
    for(int j=0; j<N; j++) {
        normu += u[j] * u[j];
        normv += v[j] * v[j];
        dotp  += u[j] * v[j];
    }
    corr = dotp / sqrt(normu*normv);
    if(normu > 0) {
        double factor = sqrt(2*N/3./normu);
        for(int j=0; j<N; j++)
        reccoeffs += (lround(u[j]*factor) == v[j]);
    }

    printf("\rSigs: [");
    for (int i = 0; i < bar_width; ++i) {
        printf("%c", (i<bar_length)?'#':' ');
    }
    printf("] %.2f%% [%.2f; %d]", progress * 100, corr, reccoeffs);
    fflush(stdout);
}

int main(int argc, char** argv)
{
    int i, j, nsamples;
    int select = 0;
    size_t smlen;
    uint8_t m[MLEN + CRYPTO_EAGLESIGN_BYTES];
    uint8_t sm[MLEN + CRYPTO_EAGLESIGN_BYTES];
    uint8_t pk[CRYPTO_EAGLESIGN_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_EAGLESIGN_SECRETKEYBYTES];

    uint8_t rho[SEEDBYTES], tr[SEEDBYTES];
    polyvecl E[K], G[L], D[K];
    double Grec[N];
    for(j=0; j<N; j++)
        Grec[j] = 0.;

    crypto_sign_keypair(pk, sk);
    unpack_sk(rho, tr, G, D, sk);
    unpack_pk(rho, E, pk);

    if(argc > 1)
        nsamples = atoi(argv[1]);
    else
        nsamples = NSAMPLES;

    printf("Attack on EagleSign-%d with %d samples...\n\n",
            EAGLESIGN_MODE, nsamples);
    for (i = 0; i < nsamples; i++) {
        if(i%25 == 0)
            print_progress(i, nsamples, Grec, G[0].vec[0].coeffs);

        randombytes(m, MLEN);

        crypto_sign(sm, &smlen, m, MLEN, sk);

        uint8_t mu[CRHBYTES], c[SEEDBYTES], r[SEEDBYTES];
        polyvecl C, Z;
        polyveck W;
        keccak_state state;
        uint16_t nonce_c = 0;

        unpack_sig(r, &Z, &W, sm);

        shake256(mu, SEEDBYTES, pk, CRYPTO_EAGLESIGN_PUBLICKEYBYTES);
        shake256_init(&state);
        shake256_absorb(&state, mu, SEEDBYTES);
        shake256_absorb(&state, m, MLEN);
        shake256_finalize(&state);
        shake256_squeeze(mu, CRHBYTES, &state);

        shake256_init(&state);
        shake256_absorb(&state, r, SEEDBYTES);
        shake256_absorb(&state, mu, CRHBYTES);
        shake256_finalize(&state);
        shake256_squeeze(c, SEEDBYTES, &state);
        polyvecl_challenge_y1_c(&C, c, &nonce_c, 1);
        polyvecl_invntt_tomont(&C);

        int c0  = C.vec[0].coeffs[0];
        select += (c0 != 0);

        for(j=0; j<N; j++)
            Grec[j] += c0 * Z.vec[0].coeffs[j];
    }

    print_progress(nsamples, nsamples, Grec, G[0].vec[0].coeffs);
    printf("\n\n");

    for(j=0; j<N; j++)
        Grec[j] /= (double)nsamples;

    double dotp = 0., normG = 0., normGrec = 0., factor;
    int reccoeffs = 0;
    for(j=0; j<N; j++) {
        normGrec += Grec[j] * Grec[j];
        normG    += G[0].vec[0].coeffs[j] * G[0].vec[0].coeffs[j];
        dotp     += Grec[j] * G[0].vec[0].coeffs[j];
    }

    factor = sqrt(2.*N/normGrec/3.);
    for(int j=0; j<N; j++) {
        Grec[j] *= factor;
        reccoeffs += (lround(Grec[j]) == G[0].vec[0].coeffs[j]);
    }
    
    printf("Out of %d total signatures, %d had c[0]==1 or c[0]==-1 (%.2f%%).\n",
            nsamples, select, 100.*((double)select) / ((double)nsamples));
    printf("Correlation between recovered G and real one: %.3f.\n",
            dotp/sqrt(normG*normGrec));
    printf("Number of correctly recovered coefficients by rounding: %d/%d\n",
            reccoeffs, N);

    return 0;
}

/*
vim: ts=4 expandtab
*/
