package com.example.demo.controller;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.*;
import com.google.common.collect.Maps;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Map;

@RestController
public class DemoController {

    @Autowired
    private AWSKMS kmsClient;

    @Value("${kms.keyId}")
    private String kmsKeyId;

    private final String ALGORITHM = "AES";

    /**
     * KMS 암호화
     * @param request
     * @param response
     * @param plainText
     * @return
     */
    @RequestMapping(value = "/kms/encrypt", method = { RequestMethod.POST })
    public ResponseEntity<Map<String, Object>> encrypt (
            HttpServletRequest request,
            HttpServletResponse response,
            // 암호화를 하기 위한 문자열
            @RequestParam("plainText") String plainText
    ) throws Exception {

        /**
         * KMS에서는 봉투 암호화 방식(envelope encryption) 을 사용하도록 권장하기에 암/복호화에서 사용하기 위한 데이터 키를 생성 한다.
         * https://docs.aws.amazon.com/ko_kr/kms/latest/developerguide/concepts.html#enveloping
         * 생성된 암호화는 plaintext, ciphertextBlob 두개의 값을 제공하고 용도는 다음과 같다.
         * plaintext data key : 특정 문자를 암호화 하기 위한 용도(이 값은 암호화하고 소멸되야하는 값으로 외부에 노출되서는 안된다.)
         * ciphertextBlob data key : 암호화된 문자열을 복호화 하기 위한 용도로 사용(추후 복호화 시 사용되는 값으로 DB에 값이 같이 저장되어야 한다.)
        */
        GenerateDataKeyResult generateDataKeyResult = generateDataKey();

        // 발급받은 plainText Data Key 로 문자열을 암호화 한다.
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(generateDataKeyResult.getPlaintext().array(), ALGORITHM));

        byte[] encryptedText = cipher.doFinal(plainText.getBytes());
        String cipherText = Base64.getEncoder().encodeToString(encryptedText);
        String encryptDataKey = Base64.getEncoder().encodeToString(generateDataKeyResult.getCiphertextBlob().array());

        Map<String, Object> dataMap = Maps.newHashMap();
        // 최종 암호화 된 문자열
        dataMap.put("cipherText", cipherText);
        // 추후 복호화 시 사용되는 암호화된 문자열 (DB 등 어딘가에 암호화된 문자열과 같이 저장되어야 하는 값이다.)
        dataMap.put("encryptDataKey", encryptDataKey);

        Map<String, Object> respDataMap = Maps.newLinkedHashMap();
        respDataMap.put("respCode", "000");
        respDataMap.put("respMessage", "kms encrypt OK!");
        respDataMap.put("requestBody" , dataMap);

        return new ResponseEntity<>(respDataMap, HttpStatus.OK);
    }

    /**
     * KMS 복호화
     * @param request
     * @param response
     * @param encryptDataKey
     * @param cipherText
     * @return
     */
    @RequestMapping(value = "/kms/decrypt", method = { RequestMethod.POST })
    public ResponseEntity<Map<String, Object>> decrypt (
            HttpServletRequest request,
            HttpServletResponse response,
            // 앞서 암호화 시 생성된 복호화에서 사용될 문자열
            @RequestParam("encryptDataKey") String encryptDataKey,
            // 복호화할 문자
            @RequestParam("cipherText") String cipherText
    ) throws Exception {

        // 암호화 시 생성된 복호화 용도 문자열을 KMS통해 PlainText 를 추출 하기 위하여 복호화를 수행한다.
        ByteBuffer encryptedKey = ByteBuffer.wrap(Base64.getDecoder().decode(encryptDataKey.getBytes()));
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        DecryptResult decryptResult = kmsClient.decrypt(decryptRequest);

        // PlainText 를 추출한다음 암호화된 문자열을 복호화 한다.
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptResult.getPlaintext().array(), ALGORITHM));
        byte[] decode = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        Map<String, Object> dataMap = Maps.newHashMap();
        // 최종 복호화된 문자열
        dataMap.put("plainText", new String(decode));

        Map<String, Object> respDataMap = Maps.newLinkedHashMap();
        respDataMap.put("respCode", "000");
        respDataMap.put("respMessage", "kms decrypt OK!");
        respDataMap.put("requestBody" , dataMap);

        return new ResponseEntity<>(respDataMap, HttpStatus.OK);
    }

    /**
     * 봉투 암호화(envelope encryption) 방식을 사용하기 위한 암호화 키 생성
     * @return
     */
    private GenerateDataKeyResult generateDataKey(){
        GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
        // DEV, PRD 환경에 맞는 KMS Key ID ARN
        dataKeyRequest.setKeyId(kmsKeyId);
        // 암호화 알고리즘 방식 선언 (AES128 or AES256)
        dataKeyRequest.setKeySpec(DataKeySpec.AES_256);
        GenerateDataKeyResult dataKeyResult = kmsClient.generateDataKey(dataKeyRequest);

        return dataKeyResult;
    }
}
