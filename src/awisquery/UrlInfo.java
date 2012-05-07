
/*
* To change this template, choose Tools | Templates
* and open the template in the editor.
 */
package awisquery;

//~--- non-JDK imports --------------------------------------------------------

import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.xml.sax.InputSource;

import sun.misc.BASE64Encoder;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author ajith
 */
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

import java.security.SignatureException;

import java.text.SimpleDateFormat;

import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Makes a request to the Alexa Web Information Service UrlInfo action.
 */
public class UrlInfo {
    private static final String ACTION_NAME         = "SitesLinkingIn";
    private static final String DATEFORMAT_AWS      = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    private static final String HASH_ALGORITHM      = "HmacSHA256";
    private static final String RESPONSE_GROUP_NAME = "SitesLinkingIn";
    private static final String SERVICE_HOST        = "awis.amazonaws.com";
    private static final String AWS_BASE_URL        = "http://" + SERVICE_HOST + "/?";
    private static ArrayList    myarray             = new ArrayList();
    private static Iterator     itr                 = myarray.iterator();
    private String              accessKeyId;
    private String              secretAccessKey;
    private String              site;

    public UrlInfo(String accessKeyId, String secretAccessKey, String site) {
        this.accessKeyId     = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.site            = site;
    }

    private static String getCharacterDataFromElement(Element e) {
        Node child = e.getFirstChild();

        if (child instanceof CharacterData) {
            CharacterData cd = (CharacterData) child;

            return cd.getData();
        }

        return "?";
    }

    private static void parseXmlFile(String xmlResponse) {
        String restitle;

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder        db  = dbf.newDocumentBuilder();
            InputSource            is  = new InputSource();

            is.setCharacterStream(new StringReader(xmlResponse));

            Document doc   = db.parse(is);
            NodeList nodes = doc.getElementsByTagName("aws:Site");


            // iterate the employees
            for (int i = 0; i < 5; i++) {
                Element  element = (Element) nodes.item(i);
                NodeList title   = element.getElementsByTagName("aws:Title");
                Element  line    = (Element) title.item(0);

                restitle = getCharacterDataFromElement(line);
                myarray.add(restitle);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a timestamp for use with AWS request signing
     *
     * @param date current date
     * @return timestamp
     */
    protected static String getTimestampFromLocalTime(Date date) {
        SimpleDateFormat format = new SimpleDateFormat(DATEFORMAT_AWS);

        format.setTimeZone(TimeZone.getTimeZone("GMT"));

        return format.format(date);
    }

    /**
     * Computes RFC 2104-compliant HMAC signature.
     *
     * @param data The data to be signed.
     * @return The base64-encoded RFC 2104-compliant HMAC signature.
     * @throws java.security.SignatureException
     *          when signature generation fails
     */
    protected String generateSignature(String data) throws java.security.SignatureException {
        String result;

        try {

            // get a hash key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(secretAccessKey.getBytes(), HASH_ALGORITHM);

            // get a hasher instance and initialize with the signing key
            Mac mac = Mac.getInstance(HASH_ALGORITHM);

            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes());

            // base64-encode the hmac
            // result = Encoding.EncodeBase64(rawHmac);
            result = new BASE64Encoder().encode(rawHmac);
        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }

        return result;
    }

    /**
     * Makes a request to the specified Url and return the results as a String
     *
     * @param requestUrl url to make request to
     * @return the XML document as a String
     * @throws IOException
     */
    public static String makeRequest(String requestUrl) throws IOException {
        URL           url  = new URL(requestUrl);
        URLConnection conn = url.openConnection();
        InputStream   in   = conn.getInputStream();

        // Read the response
        StringBuffer sb = new StringBuffer();
        int          c;
        int          lastChar = 0;

        while ((c = in.read()) != -1) {
            if ((c == '<') && (lastChar == '>')) {
                sb.append('\n');
            }

            sb.append((char) c);
            lastChar = c;
        }

        in.close();

        return sb.toString();
    }

    /**
     * Builds the query string
     */
    protected String buildQuery() throws UnsupportedEncodingException {
        String              timestamp   = getTimestampFromLocalTime(Calendar.getInstance().getTime());
        Map<String, String> queryParams = new TreeMap<String, String>();

        queryParams.put("Action", ACTION_NAME);
        queryParams.put("ResponseGroup", RESPONSE_GROUP_NAME);
        queryParams.put("AWSAccessKeyId", accessKeyId);
        queryParams.put("Timestamp", timestamp);
        queryParams.put("Url", site);
        queryParams.put("SignatureVersion", "2");
        queryParams.put("SignatureMethod", HASH_ALGORITHM);
        queryParams.put("Count", "20");
        queryParams.put("Start", "0");

        String  query = "";
        boolean first = true;

        for (String name : queryParams.keySet()) {
            if (first) {
                first = false;
            } else {
                query += "&";
            }

            query += name + "=" + URLEncoder.encode(queryParams.get(name), "UTF-8");
        }

        return query;
    }

    /**
     * Makes a request to the Alexa Web Information Service UrlInfo action
     */
    public static void main(String[] args) throws Exception {

        // Read command line parameters
        String         accessKey = "AKIAILVUUGN7EMEJCBYA";
        String         secretKey = "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";
        String         site      = "";
        BufferedReader in        = new BufferedReader(new FileReader("test_input.txt"));

        while ((site = in.readLine()) != null) {
            System.out.println("site = " + site);

            UrlInfo urlInfo = new UrlInfo(accessKey, secretKey, site);
            String  query   = urlInfo.buildQuery();
            String  toSign  = "GET\n" + SERVICE_HOST + "\n/\n" + query;

            System.out.println("String to sign:\n" + toSign + "\n");

            String signature = urlInfo.generateSignature(toSign);
            String uri       = AWS_BASE_URL + query + "&Signature=" + URLEncoder.encode(signature, "UTF-8");

            System.out.println("Making request to:\n");
            System.out.println(uri + "\n");

            // Make the Request
            String xmlResponse = makeRequest(uri);

            // Print out the XML Response
            System.out.println("Response:\n");

         //   System.out.println(xmlResponse);
            System.out.println("End of xml.........");
            parseXmlFile(xmlResponse);
        }


        System.out.println(myarray);

        Map<Object, Integer> sitecount = new HashMap<Object, Integer>();

        for (Object each : myarray) {
            Integer count = sitecount.get(each);

            sitecount.put(each, (count == null)? 1 : count + 1);
        }

        System.out.println(sitecount);
    }
}


//~ Formatted by Jindent --- http://www.jindent.com
