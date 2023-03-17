package org.sst;

import dnl.utils.text.table.TextTable;
import org.apache.commons.cli.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.pkcs11.jacknji11.*;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SecureSigningTool {
    private static final Log log = LogFactory.getLog(SecureSigningTool.class);

    private static final Option HSM_SLOT = new Option("hsm_slot", true, "HSM Slot");
    private static final Option P11_LIB = new Option("p11library", true, "Path to PKCS#11 library .so file");
    private static final Option HSM_SLOT_PWD = new Option("hsm_slot_pwd", true, "HSM slot password");
    private static final Option KEY_REF = new Option("key_ref", true, "Key Reference");
    private static final Option HASH_ALGO = new Option("hash_algorithm", true, "Hash algorithm");
    private static final Option PATH = new Option("path", true, "Path of data to be signed");

    private static byte[] USER_PIN;
    private static long INITSLOT;

    public static void setUp(CommandLine cmd) {

        INITSLOT = Long.parseLong(cmd.getOptionValue(HSM_SLOT.getOpt()));
        USER_PIN = cmd.getOptionValue(HSM_SLOT_PWD.getOpt()).getBytes();
        String p11library = cmd.getOptionValue(P11_LIB.getOpt());

        // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such
        // as:
        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(p11library);
        CE.Initialize();
    }

    public void tearDown() {
        CE.Finalize();
    }

    /**
     * Login to slotID and returns the session handle.
     *
     * @param slotID      the slot's ID
     * @param userPIN     the normal user's PIN
     * @param flags       from CK_SESSION_INFO
     * @param application passed to callback (ok to leave it null)
     * @param notify      callback function (ok to leave it null)
     * @return session handle
     */
    public static long loginSession(long slotID, byte[] userPIN, long flags, NativePointer application,
                                    CK_NOTIFY notify) {
        try {
            long session = CE.OpenSession(slotID, flags, application, notify);
            CE.LoginUser(session, userPIN);
            return session;
        }catch (CKRException rv) {
            throw new RuntimeException(rv);
        }
    }

    public static String getEcAlgo(CKA ecParams){
        ASN1ObjectIdentifier oid = null;
        String algo = null;

        if(ecParams.getValueStr() != null && ecParams.getValueStr().equals("edwards25519")){
            algo = "Ed25519";
        }else if(ecParams.getValueStr() != null) {
            try (ASN1InputStream stream = new ASN1InputStream(ecParams.getValue())) {
                final ASN1Primitive primitive = stream.readObject();
                if (primitive instanceof ASN1String) {
                    final ASN1String string = (ASN1String) primitive;
                    if ("curve25519".equalsIgnoreCase(string.getString())) {
                        algo = "Ed25519";
                    } else if ("Ed25519".equalsIgnoreCase(string.getString())) {
                        algo = "Ed25519";
                    } else if ("curve448".equalsIgnoreCase(string.getString())) {
                        algo = "Ed448";
                    }
                } else {
                    oid = ASN1ObjectIdentifier.getInstance(ecParams.getValue());
                    algo = ECNamedCurveTable.getName(oid);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return algo;
    }
    public static void privateKeyList(){

        long session = loginSession(INITSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        CKA[] templ = {
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
        };


        long[] keyRefs = CE.FindObjects(session, templ);

        Object[][] data = new Object[keyRefs.length][5];
        int i = 0;

        for(long key : keyRefs){
            String label = CE.GetAttributeValue(session,key,CKA.LABEL).getValueStr();
            String id = CE.GetAttributeValue(session,key,CKA.ID).getValueStr();
            long key_type = CE.GetAttributeValue(session,key,CKA.KEY_TYPE).getValueLong();
            CKA ecParams = CE.GetAttributeValue(session,key,CKA.EC_PARAMS);
            //BigInteger modulus = CE.GetAttributeValue(session,key,CKA.MODULUS).getValueBigInt();
            Long modulusBits = CE.GetAttributeValue(session,key,CKA.MODULUS_BITS).getValueLong();
            //BigInteger rsaExponent = CE.GetAttributeValue(session,key,CKA.PUBLIC_EXPONENT).getValueBigInt();

            String algo = getEcAlgo(ecParams);

            if(label != null){
                label = label.substring(0, label.length() - 8);
            }else{
                label = id;
            }

            /*
            System.out.println("Key Ref: " + key);
            System.out.println("Name: " + label);
            //System.out.println("ID: " + id);
            System.out.println("Key Type: " + CKK.L2S(key_type));
            if(algo != null){
                System.out.println("EC Params: " + algo);
            }
            //System.out.println("Key Size: " + modulusBits);
            //System.out.println("RSA Modulus: " + modulus);
            //System.out.println("RSA Public Exponent: " + rsaExponent);
            //System.out.println("----------------------------------------------\n");

            */
            data[i][0] = key;
            data[i][1] = label;
            data[i][2] = CKK.L2S(key_type);
            data[i][3] = algo;
            data[i][4] = modulusBits;
            i = i+1;
        }

        String[] columnNames = {"Key Ref", "Alias", "Key Type", "EC Params", "Key Size"};
        TextTable tt = new TextTable(columnNames, data);
        tt.printTable();
    }

    public static void sign(String key, String hashAlgo, String path){
        long session = loginSession(INITSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        Long privateKey = Long.parseLong(key);

        CKA ecParams = CE.GetAttributeValue(session,privateKey,CKA.EC_PARAMS);
        String ecAlgo = getEcAlgo(ecParams);
        System.out.println(key);
        System.out.println(hashAlgo);
        System.out.println(path);
        String data = "";
        try {
            data = new String(Files.readAllBytes(Paths.get(path)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.print("\n" + data.length() + "\n");

        if(hashAlgo == null || hashAlgo.toUpperCase().equals("NONE") || ecAlgo.equals("Ed25519")){
            log.info("Hash algorithm not specified, signing data");

            CE.SignInit(session, new CKM(CKM.ECDSA), privateKey);
            byte[] sig = CE.Sign(session, data.getBytes());

            byte[] base64 = Base64.getEncoder().encode(sig);

            System.out.println("Sig: " + Hex.b2s(sig));
            System.out.println("Base 64: " + new String(base64));
        }else{
            log.info("Hashing with " + hashAlgo + " then signing data");
            try {
                MessageDigest digest = MessageDigest.getInstance(hashAlgo);
                byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

                CE.SignInit(session, new CKM(CKM.ECDSA), privateKey);
                byte[] sig = CE.Sign(session, hash);

                byte[] base64 = Base64.getEncoder().encode(sig);

                System.out.println("Sig: " + Hex.b2s(sig));
                System.out.println("Base 64: " + new String(base64));

            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            catch (CKRException rv) {
                throw new RuntimeException(rv);
            }
        }
    }

    public static void main (String[] args) throws ParseException {
        if(args[0].equals("version")){
            System.out.println("sst 0.1");
        }else if(args[0].equals("listKeys")){
            Options options = new Options();
            options.addOption(HSM_SLOT);
            options.addOption(HSM_SLOT_PWD);
            options.addOption(P11_LIB);
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse( options, args);

            if(cmd.hasOption(HSM_SLOT.getOpt()) && cmd.hasOption(HSM_SLOT_PWD.getOpt()) && cmd.hasOption(P11_LIB.getOpt())){
                setUp(cmd);
                privateKeyList();
            }else{
                System.out.println("Missing arguments");
            }

        }else if(args[0].equals("sign")){
            Options options = new Options();
            options.addOption(HSM_SLOT);
            options.addOption(HSM_SLOT_PWD);
            options.addOption(P11_LIB);
            options.addOption(KEY_REF);
            options.addOption(HASH_ALGO);
            options.addOption(PATH);
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse( options, args);

            if(cmd.hasOption(HSM_SLOT.getOpt()) && cmd.hasOption(HSM_SLOT_PWD.getOpt()) && cmd.hasOption(P11_LIB.getOpt()) && cmd.hasOption(KEY_REF.getOpt()) && cmd.hasOption(PATH.getOpt())){
                setUp(cmd);
                sign(cmd.getOptionValue(KEY_REF.getOpt()), cmd.getOptionValue(HASH_ALGO.getOpt()), cmd.getOptionValue(PATH.getOpt()));
            }else{
                System.out.println("Missing arguments");
            }

        }
    }
}