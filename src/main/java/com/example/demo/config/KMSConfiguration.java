package com.example.demo.config;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KMSConfiguration {

    @Value("${kms.region}")
    private String region;

    /**
     * AWS Credentials 를 사용하기 위한 용도
     * @return
     */
    @Bean
    public AWSCredentialsProvider awsCredentialsProvider(){
        return new DefaultAWSCredentialsProviderChain();
    }

    /**
     * AWS SDK KMS Client를 생성하기 위한 용도
     * @param awsCredentialsProvider
     * @return
     */
    @Bean(name = "kmsClient")
    public AWSKMS kmsClient(AWSCredentialsProvider awsCredentialsProvider){
        return AWSKMSClientBuilder.standard()
                .withCredentials(awsCredentialsProvider)
                .withRegion(region)
                .build();
    }

}
