package org.sst;

import dnl.utils.text.table.TextTable;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.pkcs11.jacknji11.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SecureSigningTool {
    private static final Option HSM_SLOT = new Option("hsm_slot", true, "HSM Slot");
    private static final Option P11_LIB = new Option("p11library", true, "Path to PKCS#11 library .so file");
    private static final Option HSM_SLOT_PWD = new Option("hsm_slot_pwd", true, "HSM slot password");
    private static final Option KEY_REF = new Option("key_ref", true, "Key Reference");
    private static final Option HASH_ALGO = new Option("hash_algorithm", true, "Hash algorithm");
    private static final Option PATH = new Option("path", true, "Path of data to be signed");

    private static final Option VERBOSE = new Option("verbose", false, "verbose mode");

    private static boolean verbose = false;

    private static byte[] USER_PIN;
    private static long INITSLOT;

    /**
     * Initializes the CE on startup
     *
     * @param cmd command arguments
     */
    public static void setUp(CommandLine cmd) {

        INITSLOT = Long.parseLong(cmd.getOptionValue(HSM_SLOT.getOpt()));
        USER_PIN = cmd.getOptionValue(HSM_SLOT_PWD.getOpt()).getBytes();
        String p11library = cmd.getOptionValue(P11_LIB.getOpt());

        C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(p11library);

        try {
            CE.Initialize();
        }catch (CKRException rv){
            throw new RuntimeException(rv);
        }
    }

    /**
     * Destoys CE
     */
    public static void tearDown() {
        try{
            CE.Finalize();
        }catch (CKRException rv){
            throw new RuntimeException(rv);
        }
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

    /**
     * Identifies the Elliptic Curve algorithm
     *
     * @param ecParams Elliptic Curve parameters
     * @return String Name of the curve
     */
    public static String getEcAlgo(CKA ecParams){
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
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(ecParams.getValue());
                    algo = ECNamedCurveTable.getName(oid);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return algo;
    }

    /**
     * Displays the list of private keys in the slot.
     */
    public static void privateKeyList(){

        try {
            long session = loginSession(INITSLOT, USER_PIN,
                    CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

            CKA[] templ = {
                    new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            };

            long[] keyRefs = CE.FindObjects(session, templ);

            Object[][] data = new Object[keyRefs.length][5];
            int i = 0;

            for (long key : keyRefs) {
                String label = CE.GetAttributeValue(session, key, CKA.LABEL).getValueStr();
                String id = CE.GetAttributeValue(session, key, CKA.ID).getValueStr();
                long key_type = CE.GetAttributeValue(session, key, CKA.KEY_TYPE).getValueLong();
                CKA ecParams = CE.GetAttributeValue(session, key, CKA.EC_PARAMS);
                //BigInteger modulus = CE.GetAttributeValue(session,key,CKA.MODULUS).getValueBigInt();
                Long modulusBits = CE.GetAttributeValue(session, key, CKA.MODULUS_BITS).getValueLong();
                //BigInteger rsaExponent = CE.GetAttributeValue(session,key,CKA.PUBLIC_EXPONENT).getValueBigInt();

                String algo = getEcAlgo(ecParams);

                if (label != null) {
                    label = label.substring(0, label.length() - 8);
                } else {
                    label = id;
                }

                data[i][0] = key;
                data[i][1] = label;
                data[i][2] = CKK.L2S(key_type);
                data[i][3] = algo;
                data[i][4] = modulusBits;
                i = i + 1;
            }

            String[] columnNames = {"Key Ref", "Alias", "Key Type", "EC Params", "Key Size"};
            TextTable tt = new TextTable(columnNames, data);
            tt.printTable();

            CE.CloseSession(session);
            tearDown();
        }catch (CKRException rv){
            throw new RuntimeException(rv);
        }
    }
    /**
     * Signs data with following hash algorithm and private key.
     * Displays the signature in Base64
     * @param key Private Key Reference
     * @param hashAlgo Hashing algorithm
     * @param path file path to sign
     */
    public static void sign(String key, String hashAlgo, String path){
        try{
            long session = loginSession(INITSLOT, USER_PIN,
                    CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
            long privateKey = Long.parseLong(key);

            CKA ecParams = CE.GetAttributeValue(session,privateKey,CKA.EC_PARAMS);
            String ecAlgo = "";
            byte[] data;

            if(ecParams.getValueStr() != null){
                ecAlgo = getEcAlgo(ecParams);
            }


            data = Files.readAllBytes(Paths.get(path));


            if(hashAlgo == null || hashAlgo.equalsIgnoreCase("NONE") || ecAlgo.equals("Ed25519")){

                CE.SignInit(session, new CKM(CKM.ECDSA), privateKey);
                byte[] sig = CE.Sign(session, data);

                byte[] base64 = Base64.getEncoder().encode(sig);

                if(verbose){
                    FileInputStream derCheck = new FileInputStream(path);
                    // Check first byte for DER tag value
                    int tag = derCheck.read();
                    derCheck.close();
                    if (tag == 0x30) {
                        System.out.println("Found DER Tag\n");
                        FileInputStream certRead = new FileInputStream(path);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(certRead);
                        certRead.close();
                        System.out.println(cert);
                    }


                    System.out.println("\nData to sign (HEX)\n" + Hex.b2s(data));
                    System.out.println("\nSignature (HEX)\n" + Hex.b2s(sig) + "\n");
                }

                System.out.println(new String(base64));

                verify(sig, data, privateKey, session);

            }else{
                System.out.println("Only Ed25519 currently supported");
                System.exit(1);


                MessageDigest digest = MessageDigest.getInstance(hashAlgo);
                byte[] hash = digest.digest(data);

                CE.SignInit(session, new CKM(CKM.ECDSA), privateKey);
                byte[] sig = CE.Sign(session, hash);

                byte[] base64 = Base64.getEncoder().encode(sig);

                System.out.println(new String(base64));

            }

            CE.CloseSession(session);
            tearDown();

        }catch (CKRException | IOException | NoSuchAlgorithmException | CertificateException rv){
            throw new RuntimeException(rv);
        }
    }

    public static void verify(byte[] sig, byte[] data, long key, long session){
        String label = CE.GetAttributeValue(session, key, CKA.LABEL).getValueStr();
        String id = CE.GetAttributeValue(session, key, CKA.ID).getValueStr();

        if (label != null) {
            label = label.substring(0, label.length() - 8);
        } else {
            label = id;
        }

        CKA[] templ = {
                new CKA(CKA.LABEL, label+"-public"),
        };
        try {
            long[] keyRefs = CE.FindObjects(session, templ);

            CE.VerifyInit(session, new CKM(CKM.ECDSA), keyRefs[0]);
            CE.Verify(session, data, sig);
            if(verbose){
                System.out.println("Valid Signature verified");
            }
        }catch (CKRException rv){
            throw new RuntimeException("Valid signature verification failed", rv);
        }

    }

    public static void main (String[] args) throws ParseException {
        String argument;
        if(args.length == 0){argument = "default";}
        else{argument = args[0];}

        switch (argument) {
            case "version":
                System.out.println("sst v0.1");
                break;
            case "listKeys": {
                Options options = new Options();
                options.addOption(HSM_SLOT);
                options.addOption(HSM_SLOT_PWD);
                options.addOption(P11_LIB);
                CommandLineParser parser = new DefaultParser();
                CommandLine cmd = parser.parse(options, args);

                if (cmd.hasOption(HSM_SLOT.getOpt()) && cmd.hasOption(HSM_SLOT_PWD.getOpt()) && cmd.hasOption(P11_LIB.getOpt())) {
                    setUp(cmd);
                    privateKeyList();
                } else {
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing HSM Slot");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing HSM PWD");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing P11 Library");}
                }

                break;
            }
            case "sign": {
                Options options = new Options();
                options.addOption(HSM_SLOT);
                options.addOption(HSM_SLOT_PWD);
                options.addOption(P11_LIB);
                options.addOption(KEY_REF);
                options.addOption(HASH_ALGO);
                options.addOption(PATH);
                options.addOption(VERBOSE);
                CommandLineParser parser = new DefaultParser();
                CommandLine cmd = parser.parse(options, args);

                if (cmd.hasOption(HSM_SLOT.getOpt()) && cmd.hasOption(HSM_SLOT_PWD.getOpt()) && cmd.hasOption(P11_LIB.getOpt()) && cmd.hasOption(KEY_REF.getOpt()) && cmd.hasOption(PATH.getOpt())) {
                    setUp(cmd);
                    if(cmd.hasOption(VERBOSE.getOpt())){verbose = true;}
                    sign(cmd.getOptionValue(KEY_REF.getOpt()), cmd.getOptionValue(HASH_ALGO.getOpt()), cmd.getOptionValue(PATH.getOpt()));
                } else {
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing HSM Slot");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing HSM PWD");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing P11 Library");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing Key Ref");}
                    if(!cmd.hasOption(HSM_SLOT)){System.out.println("Missing file path");}
                }

                break;
            }
            default:
                HelpFormatter formatter = new HelpFormatter();

                Options options = new Options();
                formatter.printHelp("SecureSigningTool version", "Print the version of the application\n", options, "", true);
                formatter.printHelp("SecureSigningTool -h", "Help Screen\n", options, "", true);

                options.addOption(HSM_SLOT);
                options.addOption(HSM_SLOT_PWD);
                options.addOption(P11_LIB);

                formatter.printHelp("SecureSigningTool listKeys", "Lists all of the private keys in the slot, including, name of the key, key reference, private key algorithm\n\n", options, "", true);


                options.addOption(KEY_REF);
                options.addOption(HASH_ALGO);
                options.addOption(VERBOSE);
                options.addOption(PATH);
                System.out.println("\n");

                formatter.printHelp("SecureSigningTool sign", "Signs file and displays the signature as Base64\n\n", options, "", true);
                System.out.println("\nPlease report issues at https://github.com/devisefutures/sst");

                break;
        }
    }
}
