package jp.comutt.otp;

import jp.comutt.otp.OtpauthUri.InvalidUriException;
import junit.framework.TestCase;


public class OtpauthUriTest extends TestCase {

    public void testParse_shouldThrowInvalidUriException_ifUriIsNull() throws Exception {
        try {
            OtpauthUri.parse(null);
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri is null");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifUriIsEmpty() throws Exception {
        try {
            OtpauthUri.parse("");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri is empty");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifUriDoesNotStartsWithOtpauth() throws Exception {
        try {
            OtpauthUri.parse("http://");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri does not starts with otpauth://");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifUriDoesNotHaveSlash() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri does not have /");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifTypeIsUnknown() throws Exception {
        try {
            OtpauthUri.parse("otpauth://hoge/");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "unknown otp type: type=hoge");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifNoParameters() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp/ISSUER%3ALABEL");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri does not have parameters");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifEmptyParameter() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp/ISSUER%3ALABEL?");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri have empty parameter");
        }
    }

    public void testParse_shouldReturnValidInstance_ifNoSecret() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp/foo.bar%2Bbaz%40example.com?period=30");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri does not have secret");
        }
    }

    public void testParse_shouldReturnValidInstance_ifTotpAndLabelAndSecret() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://totp/foo.bar%2Bbaz%40example.com?secret=SEC%20RET");

        assertEquals(uri.getType(), OtpauthUri.TokenType.TOTP);
        assertNull(uri.getIssuer());
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertNull(uri.getAlgorithm());
        assertNull(uri.getDigits());
        assertNull(uri.getPeriod());
        assertNull(uri.getImage());
        assertNull(uri.getCounter());
    }

    public void testParse_shouldReturnValidInstance_ifTotpAndLabelAndSecretAndIssuerParam() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://totp/foo.bar%2Bbaz%40example.com?secret=SEC%20RET&issuer=COMPANY");

        assertEquals(uri.getType(), OtpauthUri.TokenType.TOTP);
        assertEquals(uri.getIssuer(), "COMPANY");
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertNull(uri.getAlgorithm());
        assertNull(uri.getDigits());
        assertNull(uri.getPeriod());
        assertNull(uri.getImage());
        assertNull(uri.getCounter());
    }

    public void testParse_shouldReturnValidInstance_ifTotpAndIssuerAndLabelAndSecret() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://totp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET");

        assertEquals(uri.getType(), OtpauthUri.TokenType.TOTP);
        assertEquals(uri.getIssuer(), "ISSUER");
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertNull(uri.getAlgorithm());
        assertNull(uri.getDigits());
        assertNull(uri.getPeriod());
        assertNull(uri.getImage());
        assertNull(uri.getCounter());
    }

    public void testParse_shouldReturnValidInstance_ifTotpAndIssuerAndLabelAndSecretAndIssuerParam() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://totp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&issuer=COMAPNY");

        assertEquals(uri.getType(), OtpauthUri.TokenType.TOTP);
        assertEquals(uri.getIssuer(), "COMAPNY");
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertNull(uri.getAlgorithm());
        assertNull(uri.getDigits());
        assertNull(uri.getPeriod());
        assertNull(uri.getImage());
        assertNull(uri.getCounter());
    }

    public void testParse_shouldReturnValidInstance_ifTotpAndIssuerAndLabelAndSecretAndAlgoAndDigitsAndPeriodAndImage() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://totp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&algorithm=sha1&digits=6&period=30&image=http%3A%2F%2Fexample.com%2Fexample.jpg");

        assertEquals(uri.getType(), OtpauthUri.TokenType.TOTP);
        assertEquals(uri.getIssuer(), "ISSUER");
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertEquals(uri.getAlgorithm(), "sha1");
        assertEquals(uri.getDigits().intValue(), 6);
        assertEquals(uri.getPeriod().intValue(), 30);
        assertEquals(uri.getImage(), "http://example.com/example.jpg");

        assertNull(uri.getCounter());
    }

    public void testParse_shouldThrowInvalidUriException_ifTotpAndInvalidDigits() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&algorithm=sha1&digits=X");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri has invalid digits: digits=X");
        }
    }

    public void testParse_shouldThrowInvalidUriException_ifTotpAndInvalidPeriod() throws Exception {
        try {
            OtpauthUri.parse("otpauth://totp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&algorithm=sha1&period=");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri has invalid period: period=");
        }
    }

    public void testParse_shouldReturnValidInstance_ifHotpAndIssuerAndLabelAndSecretAndAlgoAndDigitsAndPeriod() throws Exception {
        OtpauthUri uri = OtpauthUri.parse("otpauth://hotp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&counter=1234512345678");

        assertEquals(uri.getType(), OtpauthUri.TokenType.HOTP);
        assertEquals(uri.getIssuer(), "ISSUER");
        assertEquals(uri.getLabel(), "foo.bar+baz@example.com");
        assertEquals(uri.getSecret(), "SEC RET");
        assertEquals(uri.getCounter().longValue(), 1234512345678L);
        assertNull(uri.getAlgorithm());
        assertNull(uri.getDigits());
        assertNull(uri.getPeriod());
        assertNull(uri.getImage());
    }

    public void testParse_shouldThrowInvalidUriException_ifHotpAndInvalidCounter() throws Exception {
        try {
            OtpauthUri.parse("otpauth://hotp/ISSUER%3Afoo.bar%2Bbaz%40example.com?secret=SEC%20RET&counter=Z");
            fail("never reach here");
        } catch (Exception e) {
            assertEquals(e.getClass(), InvalidUriException.class);
            assertEquals(e.getMessage(), "uri has invalid counter: counter=Z");
        }
    }

}
