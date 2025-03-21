/**************************************************************************************
* Filename:   test.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2025
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

static uint8_t ellipticCurvesOI[15][11] = {{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01, 0x00},
                                           {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x00},
                                           {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B},
                                           {0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D}};

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
        brainpoolP160r1
    */
    ecs[8]->p = bigIntegerFromString("E95E4A5F737059DC60DFC7AD95B3D8139515620F",16,1);
    ecs[8]->a = bigIntegerFromString("340E7BE2A280EB74E2BE61BADA745D97E8F7C300",16,1);
    ecs[8]->b = bigIntegerFromString("1E589A8595423412134FAA2DBDEC95C8D8675E58",16,1);
    ecs[8]->Gx = bigIntegerFromString("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",16,1);
    ecs[8]->Gy = bigIntegerFromString("1667CB477A1A8EC338F94741669C976316DA6321",16,1);
    ecs[8]->n = bigIntegerFromString("E95E4A5F737059DC60DF5991D45029409E60FC09",16,1);
    ecs[8]->ec = BRAINPOOLP160R1;
    ecs[8]->oid = ellipticCurvesOI[8];
    ecs[8]->oidlen = 11;
    sprintf(ecs[8]->name,"%s","brainpoolP160r1");

    /*
        brainpoolP192r1
    */
    ecs[9]->p = bigIntegerFromString("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",16,1);
    ecs[9]->a = bigIntegerFromString("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",16,1);
    ecs[9]->b = bigIntegerFromString("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",16,1);
    ecs[9]->Gx = bigIntegerFromString("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",16,1);
    ecs[9]->Gy = bigIntegerFromString("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",16,1);
    ecs[9]->n = bigIntegerFromString("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1",16,1);
    ecs[9]->ec = BRAINPOOLP192R1;
    ecs[9]->oid = ellipticCurvesOI[9];
    ecs[9]->oidlen = 11;
    sprintf(ecs[9]->name,"%s","brainpoolP192r1");

    /*
        brainpoolP224r1
    */
    ecs[10]->p = bigIntegerFromString("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",16,1);
    ecs[10]->a = bigIntegerFromString("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",16,1);
    ecs[10]->b = bigIntegerFromString("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",16,1);
    ecs[10]->Gx = bigIntegerFromString("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",16,1);
    ecs[10]->Gy = bigIntegerFromString("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",16,1);
    ecs[10]->n = bigIntegerFromString("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",16,1);
    ecs[10]->ec = BRAINPOOLP224R1;
    ecs[10]->oid = ellipticCurvesOI[10];
    ecs[10]->oidlen = 11;
    sprintf(ecs[10]->name,"%s","brainpoolP224r1");

    /*
        brainpoolP256r1
    */
    ecs[11]->p = bigIntegerFromString("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",16,1);
    ecs[11]->a = bigIntegerFromString("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",16,1);
    ecs[11]->b = bigIntegerFromString("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",16,1);
    ecs[11]->Gx = bigIntegerFromString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",16,1);
    ecs[11]->Gy = bigIntegerFromString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",16,1);
    ecs[11]->n = bigIntegerFromString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",16,1);
    ecs[11]->ec = BRAINPOOLP256R1;
    ecs[11]->oid = ellipticCurvesOI[11];
    ecs[11]->oidlen = 11;
    sprintf(ecs[11]->name,"%s","brainpoolP256r1");

    /*
        brainpoolP320r1
    */
    ecs[12]->p = bigIntegerFromString("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",16,1);
    ecs[12]->a = bigIntegerFromString("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",16,1);
    ecs[12]->b = bigIntegerFromString("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",16,1);
    ecs[12]->Gx = bigIntegerFromString("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",16,1);
    ecs[12]->Gy = bigIntegerFromString("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",16,1);
    ecs[12]->n = bigIntegerFromString("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",16,1);
    ecs[12]->ec = BRAINPOOLP320R1;
    ecs[12]->oid = ellipticCurvesOI[12];
    ecs[12]->oidlen = 11;
    sprintf(ecs[12]->name,"%s","brainpoolP320r1");

    /*
        brainpoolP384r1
    */
    ecs[13]->p = bigIntegerFromString("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",16,1);
    ecs[13]->a = bigIntegerFromString("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",16,1);
    ecs[13]->b = bigIntegerFromString("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",16,1);
    ecs[13]->Gx = bigIntegerFromString("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",16,1);
    ecs[13]->Gy = bigIntegerFromString("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",16,1);
    ecs[13]->n = bigIntegerFromString("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",16,1);
    ecs[13]->ec = BRAINPOOLP384R1;
    ecs[13]->oid = ellipticCurvesOI[13];
    ecs[13]->oidlen = 11;
    sprintf(ecs[13]->name,"%s","brainpoolP384r1");

    /*
        brainpoolP512r1
    */
    ecs[14]->p = bigIntegerFromString("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",16,1);
    ecs[14]->a = bigIntegerFromString("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",16,1);
    ecs[14]->b = bigIntegerFromString("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",16,1);
    ecs[14]->Gx = bigIntegerFromString("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",16,1);
    ecs[14]->Gy = bigIntegerFromString("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",16,1);
    ecs[14]->n = bigIntegerFromString("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",16,1);
    ecs[14]->ec = BRAINPOOLP512R1;
    ecs[14]->oid = ellipticCurvesOI[14];
    ecs[14]->oidlen = 11;
    sprintf(ecs[14]->name,"%s","brainpoolP512r1");

    /*
        testec000
    */
    ecs[15]->p = bigIntegerFromString("5003",10,1);
    ecs[15]->a = bigIntegerFromString("11",10,1);
    ecs[15]->b = bigIntegerFromString("7",10,1);
    ecs[15]->Gx = bigIntegerFromString("1",10,1);
    ecs[15]->Gy = bigIntegerFromString("1",10,1);
    ecs[15]->n = bigIntegerFromString("1",10,1);
    ecs[15]->oidlen = 0;
    ecs[15]->ec = TESTEC000;
    sprintf(ecs[15]->name,"%s","testec000");

    return ecs;

errorMalloc:
    freeEllipticCurves(ecs);
    return NULL;
}
