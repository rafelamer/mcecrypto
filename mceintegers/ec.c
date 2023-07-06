/**************************************************************************************
* Filename:   test.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2023
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA and ECC encryption and decryption algorithm for 
*             educational purposes and should not be used in contexts that 
*             need cryptographically secure implementation
*	    
* License:    This library  is free software; you can redistribute it and/or
*             modify it under the terms of either:
*
*             1 the GNU Lesser General Public License as published by the Free
*               Software Foundation; either version 3 of the License, or (at your
*               option) any later version.
*
*             or
*
*             2 the GNU General Public License as published by the Free Software
*               Foundation; either version 2 of the License, or (at your option)
*               any later version.
*
*	      See https://www.gnu.org/licenses/
***************************************************************************************/
#include <mceintegers.h>

static uint8_t ellipticCurvesOI[8][10] = {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1F, 0x00, 0x00, 0x00},
                                          {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01},
                                          {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00},
                                          {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21, 0x00, 0x00, 0x00},
                                          {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x00, 0x00, 0x00},
                                          {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
                                          {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00},
                                          {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00}};

void free_elliptic_curve(EllipticCurve *ec)
{
    if (*ec != NULL)
	{
		if ((*ec)->p != NULL)
			freeBigInteger((*ec)->p);
        if ((*ec)->a != NULL)
			freeBigInteger((*ec)->a);
        if ((*ec)->b != NULL)
			freeBigInteger((*ec)->b);
        if ((*ec)->n != NULL)
			freeBigInteger((*ec)->n);
        if ((*ec)->Gx != NULL)
			freeBigInteger((*ec)->Gx);
        if ((*ec)->Gy != NULL)
			freeBigInteger((*ec)->Gy);
		free(*ec);
	}
	*ec = NULL;
}

void free_elliptic_curves(EllipticCurves *ecs)
{
    if (*ecs != NULL)
		for(int i=0;i<NISTCURVES;i++)
            freeEllipticCurve((*ecs)[i]);
    free(*ecs);
	*ecs = NULL;
}

EllipticCurves initNISTEllipticCurves()
{
    int count = 0;
    EllipticCurves ecs;
    if ((ecs = (EllipticCurves) calloc(NISTCURVES, sizeof(EllipticCurve))) == NULL)
		goto errorMalloc;
    for(int i=0;i<NISTCURVES;i++)
        if ((ecs[i] = (EllipticCurve) malloc(sizeof(elliptic_curve))) == NULL)
            goto errorMalloc;
    /*
        secp192k1
    */     
    ecs[0]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",16,1);
    ecs[0]->a = bigIntegerFromString("000000000000000000000000000000000000000000000000",16,1);
    ecs[0]->b = bigIntegerFromString("000000000000000000000000000000000000000000000003",16,1);
    ecs[0]->Gx = bigIntegerFromString("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",16,1);
    ecs[0]->Gy = bigIntegerFromString("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",16,1);
    ecs[0]->n = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",16,1);
    ecs[0]->ec = SECP192K1;
    ecs[0]->oid = ellipticCurvesOI[0];
    ecs[0]->oidlen = 7;
    sprintf(ecs[0]->name,"%s","secp192k1");

    /*
        secp192r1
    */     
    ecs[1]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",16,1);
    ecs[1]->a = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",16,1);
    ecs[1]->b = bigIntegerFromString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",16,1);
    ecs[1]->Gx = bigIntegerFromString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",16,1);
    ecs[1]->Gy = bigIntegerFromString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",16,1);
    ecs[1]->n = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",16,1);
    ecs[1]->ec = SECP192R1;
    ecs[1]->oid = ellipticCurvesOI[1];
    ecs[1]->oidlen = 10;
    sprintf(ecs[1]->name,"%s","secp192r1");
    
    /*
        secp224k1
    */     
    ecs[2]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",16,1);
    ecs[2]->a = bigIntegerFromString("00000000000000000000000000000000000000000000000000000000",16,1);
    ecs[2]->b = bigIntegerFromString("00000000000000000000000000000000000000000000000000000005",16,1);
    ecs[2]->Gx = bigIntegerFromString("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",16,1);
    ecs[2]->Gy = bigIntegerFromString("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",16,1);
    ecs[2]->n = bigIntegerFromString("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",16,1);
    ecs[2]->ec = SECP224K1;
    ecs[2]->oid = ellipticCurvesOI[2];
    ecs[2]->oidlen = 7;
    sprintf(ecs[2]->name,"%s","secp224k1");

    /*
        secp224r1
    */     
    ecs[3]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",16,1);
    ecs[3]->a = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",16,1);
    ecs[3]->b = bigIntegerFromString("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",16,1);
    ecs[3]->Gx = bigIntegerFromString("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",16,1);
    ecs[3]->Gy = bigIntegerFromString("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",16,1);
    ecs[3]->n = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",16,1);
    ecs[3]->ec = SECP224R1;
    ecs[3]->oid = ellipticCurvesOI[3];
    ecs[3]->oidlen = 7;
    sprintf(ecs[3]->name,"%s","secp224r1");

    /*
        secp256k1
    */     
    ecs[4]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16,1);
    ecs[4]->a = bigIntegerFromString("0000000000000000000000000000000000000000000000000000000000000000",16,1);
    ecs[4]->b = bigIntegerFromString("0000000000000000000000000000000000000000000000000000000000000007",16,1);
    ecs[4]->Gx = bigIntegerFromString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16,1);
    ecs[4]->Gy = bigIntegerFromString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16,1);
    ecs[4]->n = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16,1);
    ecs[4]->oid = ellipticCurvesOI[4];
    ecs[4]->oidlen = 7;
    ecs[4]->ec = SECP256K1;
    sprintf(ecs[4]->name,"%s","secp256k1");

    /*
        secp256r1
    */     
    ecs[5]->p = bigIntegerFromString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",16,1);
    ecs[5]->a = bigIntegerFromString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",16,1);
    ecs[5]->b = bigIntegerFromString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",16,1);
    ecs[5]->Gx = bigIntegerFromString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",16,1);
    ecs[5]->Gy = bigIntegerFromString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",16,1);
    ecs[5]->n = bigIntegerFromString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",16,1);
    ecs[5]->oid = ellipticCurvesOI[5];
    ecs[5]->oidlen = 10;
    ecs[5]->ec = SECP256R1;
    sprintf(ecs[5]->name,"%s","secp256r1");

    /*
        secp384r1
    */     
    ecs[6]->p = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",16,1);
    ecs[6]->a = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",16,1);
    ecs[6]->b = bigIntegerFromString("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",16,1);
    ecs[6]->Gx = bigIntegerFromString("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",16,1);
    ecs[6]->Gy = bigIntegerFromString("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",16,1);
    ecs[6]->n = bigIntegerFromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",16,1);
    ecs[6]->oid = ellipticCurvesOI[6];
    ecs[6]->oidlen = 7;
    ecs[6]->ec = SECP384R1;
    sprintf(ecs[6]->name,"%s","secp384r1");

    /*
        secp521r1
    */     
    ecs[7]->p = bigIntegerFromString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",16,1);
    ecs[7]->a = bigIntegerFromString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",16,1);
    ecs[7]->b = bigIntegerFromString("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",16,1);
    ecs[7]->Gx = bigIntegerFromString("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",16,1);
    ecs[7]->Gy = bigIntegerFromString("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",16,1);
    ecs[7]->n = bigIntegerFromString("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",16,1);
    ecs[7]->oid = ellipticCurvesOI[7];
    ecs[7]->oidlen = 7;
    ecs[7]->ec = SECP521R1;
    sprintf(ecs[7]->name,"%s","secp521r1");

    /*
        testec000
    */
    ecs[8]->p = bigIntegerFromString("5003",10,1);
    ecs[8]->a = bigIntegerFromString("11",10,1);
    ecs[8]->b = bigIntegerFromString("7",10,1);
    ecs[8]->Gx = bigIntegerFromString("1",10,1);
    ecs[8]->Gy = bigIntegerFromString("1",10,1);
    ecs[8]->n = bigIntegerFromString("1",10,1);
    ecs[8]->oidlen = 0;
    ecs[8]->ec = TESTEC000;
    sprintf(ecs[8]->name,"%s","testec000");

    return ecs;

errorMalloc:
    freeEllipticCurves(ecs);
    return NULL;
}
