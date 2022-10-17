package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.picnic;

import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.util.Arrays;

import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicSigner;
import org.bouncycastle.util.Pack;

public class PicnicCreateSigned extends TestCase
{
    public void testCreateSignPicnic() 
        throws Exception
    {
        String[] files = new String[]{
            "3/keypairs_ref_L1.rsp",
            "3/keypairs_ref_L3.rsp",
            "3/keypairs_ref_L5.rsp",
            "fs/keypairs_ref_L1.rsp",
            "fs/keypairs_ref_L3.rsp",
            "fs/keypairs_ref_L5.rsp",
            "full/keypairs_ref_L1.rsp",
            "full/keypairs_ref_L3.rsp",
            "full/keypairs_ref_L5.rsp",
            "ur/keypairs_ref_L1.rsp",
            "ur/keypairs_ref_L3.rsp",
            "ur/keypairs_ref_L5.rsp",
        };

        String[] newFiles = new String[]{
            "3/signed_java_L1.rsp",
            "3/signed_java_L3.rsp",
            "3/signed_java_L5.rsp",
            "fs/signed_java_L1.rsp",
            "fs/signed_java_L3.rsp",
            "fs/signed_java_L5.rsp",
            "full/signed_java_L1.rsp",
            "full/signed_java_L3.rsp",
            "full/signed_java_L5.rsp",
            "ur/signed_java_L1.rsp",
            "ur/signed_java_L3.rsp",
            "ur/signed_java_L5.rsp",
        };

        PicnicParameters[] paramList = new PicnicParameters[]{
            PicnicParameters.picnic3l1,
            PicnicParameters.picnic3l3,
            PicnicParameters.picnic3l5,
            PicnicParameters.picnicl1fs,
            PicnicParameters.picnicl3fs,
            PicnicParameters.picnicl5fs,
            PicnicParameters.picnicl1full,
            PicnicParameters.picnicl3full,
            PicnicParameters.picnicl5full,
            PicnicParameters.picnicl1ur,
            PicnicParameters.picnicl3ur,
            PicnicParameters.picnicl5ur,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = PicnicCreateSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));

            String line = null;
            while ((line = br.readLine()) != null){
                //Find next test
                int countIndex = line.indexOf("count = ");
                while (countIndex < 0){
                    line = br.readLine();
                    countIndex = line.indexOf("count = ");
                }
                String count = line.substring(countIndex + "count = ".length()).trim();
                line = br.readLine();
                
                //Get Seed
                int seedIndex = line.indexOf("seed = ");
                String seedString = line.substring(seedIndex + "seed = ".length()).trim();
                line = br.readLine();
                //Get Message Length
                int mlenIndex = line.indexOf("mlen = ");
                String mlenString = line.substring(mlenIndex + "mlen = ".length()).trim();
                line = br.readLine();
                //Get Message
                int messageIndex = line.indexOf("msg = ");
                String messageString = line.substring(messageIndex + "msg = ".length()).trim();
                line = br.readLine();
                //Get Public Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seedOld = Hex.decode(seedString); 
                byte[] sk = Hex.decode(secretKeyString);
                byte[] msg = Hex.decode(messageString);

                System.out.println("Testing Case: "+count);

                byte[] seed = new byte[48];
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                //Get Parameters
                PicnicParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                PicnicPrivateKeyParameters privateKeyParams = new PicnicPrivateKeyParameters(params, sk);
                
                PicnicSigner signer = new PicnicSigner();
                signer.init(true, privateKeyParams);

                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(Pack.intToLittleEndian(sigGenerated.length),msg,sigGenerated);

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("mlen = "+mlenString+"\n");
                newFile.write("msg = "+messageString+"\n");
                newFile.write("smlen = "+Integer.toString(attachedSig.length)+"\n");
                newFile.write("sm = "+Hex.toHexString(attachedSig)+"\n");

                newFile.write("\n");
                System.out.println("All Passed");
            }
            newFile.close();
        }
    }
}