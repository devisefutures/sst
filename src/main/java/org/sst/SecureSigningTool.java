package org.sst;

import org.apache.commons.cli.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.pkcs11.jacknji11.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SecureSigningTool {
    private static final Log log = LogFactory.getLog(SecureSigningTool.class);

    private static final Option HSM_SLOT = new Option("hsm_slot", true, "HSM Slot");
    private static final Option P11_LIB = new Option("p11library", true, "Path to PKCS#11 library .so file");
    private static final Option HSM_SLOT_PWD = new Option("hsm_slot_pwd", true, "HSM slot password");

    private static byte[] USER_PIN;
    private static long INITSLOT;

    private static HashMap<Long,KeyInfo> keyInfoCache = new HashMap<>();

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
        long session = CE.OpenSession(slotID, flags, application, notify);
        CE.LoginUser(session, userPIN);
        return session;
    }

    public static void privateKeyList(){
        long session = loginSession(INITSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        CKA[] templ = {
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
        };

        long[] keyRefs = CE.FindObjects(session, templ);

        for(long key : keyRefs){
            String label = CE.GetAttributeValue(session,key,CKA.LABEL).getValueStr();
            String id = CE.GetAttributeValue(session,key,CKA.ID).getValueStr();
            long key_type = CE.GetAttributeValue(session,key,CKA.KEY_TYPE).getValueLong();
            CKA ecParams = CE.GetAttributeValue(session,key,CKA.EC_PARAMS);
            BigInteger modulus = CE.GetAttributeValue(session,key,CKA.MODULUS).getValueBigInt();
            Long modulusBits = CE.GetAttributeValue(session,key,CKA.MODULUS_BITS).getValueLong();
            BigInteger rsaExponent = CE.GetAttributeValue(session,key,CKA.PUBLIC_EXPONENT).getValueBigInt();

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

            KeyInfo info = new KeyInfo(label, id, CKK.L2S(key_type), algo, modulus, modulusBits, rsaExponent);

            keyInfoCache.put(key,info);
        }

        for(Map.Entry<Long, KeyInfo> entry : keyInfoCache.entrySet()){
            System.out.println("Key Ref: " + entry.getKey());
            System.out.println("Label: " + entry.getValue().label);
            System.out.println("ID: " + entry.getValue().id);
            System.out.println("Key Type: " + entry.getValue().keyType);
            System.out.println("Key Size: " + entry.getValue().keySize);
            System.out.println("EC Params: " + entry.getValue().ecParams);
            System.out.println("RSA Modulus: " + entry.getValue().modulus);
            System.out.println("RSA Public Exponent: " + entry.getValue().rsaExponent);
            System.out.println("----------------------------------------------\n");
        }
    }

    public static void main (String[] args) throws ParseException {
        if(args[0].equals("version")){
            System.out.println("stt 0.1");
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
            }

        }else if(args[0].equals("sign")){

        }
    /*
        Options options = new Options();
        // Commands
        options.addOption("version", false, "Project Version");
        options.addOption("listKeys", true, "Lists keys at specified slot.");
        options.addOption("sign", true, "Create Signature using referenced key on specified slot.");

        //Switches

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse( options, args);

        if(cmd.hasOption("version")){
        }else if(cmd.hasOption("listKeys")){
            Properties listkeys = cmd.getOptionProperties("listKeys");

        }

     */
    }

    static public class KeyInfo{
        private String label;
        private String id;
        private String keyType;
        private String ecParams;
        private BigInteger modulus;
        private Long keySize;
        private BigInteger rsaExponent;

        public KeyInfo(String label, String id, String keyType, String ecParams, BigInteger modulus, Long keySize, BigInteger rsaExponent) {
            this.label = label;
            this.id = id;
            this.keyType = keyType;
            this.ecParams = ecParams;
            this.modulus = modulus;
            this.keySize = keySize;
            this.rsaExponent = rsaExponent;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getKeyType() {
            return keyType;
        }

        public void setKeyType(String keyType) {
            this.keyType = keyType;
        }

        public String getEcParams() {
            return ecParams;
        }

        public void setEcParams(String ecParams) {
            this.ecParams = ecParams;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        public void setModulus(BigInteger modulus) {
            this.modulus = modulus;
        }

        public BigInteger getRsaExponent() {
            return rsaExponent;
        }

        public void setRsaExponent(BigInteger rsaExponent) {
            this.rsaExponent = rsaExponent;
        }

        public Long getKeySize() {
            return keySize;
        }

        public void setKeySize(Long keySize) {
            this.keySize = keySize;
        }
    }
}