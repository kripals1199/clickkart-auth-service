// src/main/java/com/clickkart/auth/serviceImpl/OtpServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.config.AuthProperties;
import com.clickkart.auth.entity.ClickKartUserEntity;
import com.clickkart.auth.entity.LoginOtpEntity;
import com.clickkart.auth.enums.OtpChannel;
import com.clickkart.auth.exception.InvalidOtpException;
import com.clickkart.auth.jwt.JwtService;
import com.clickkart.auth.repository.LoginOtpRepository;
import com.clickkart.auth.service.AuthFailureRecorder;
import com.clickkart.auth.service.OtpService;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class OtpServiceImpl implements OtpService {

	private static final String GENERIC_REJECTION_MESSAGE = "OTP is invalid, expired, or was never requested";

	private final LoginOtpRepository loginOtpRepository;
	private final JwtService jwtService;
	private final AuthProperties authProperties;
	private final AuthFailureRecorder authFailureRecorder;

	@Override
	@Transactional(rollbackFor = Exception.class)
	public IssuedOtp issue(ClickKartUserEntity clickKartUser, OtpChannel channel, String correlationId, Instant now) {
		loginOtpRepository.invalidateAllOutstandingForUser(clickKartUser, now);

		String rawValue = jwtService.generateNumericOtp(authProperties.getOtpLength());
		System.out.println("rawValue==> "+rawValue);
		LoginOtpEntity entity = new LoginOtpEntity(clickKartUser, jwtService.hashToken(rawValue), channel,correlationId, now.plusSeconds(authProperties.getOtpTtlSeconds()));
		return new IssuedOtp(loginOtpRepository.save(entity), rawValue);
	}

	@Override
	@Transactional(rollbackFor = Exception.class)
	public LoginOtpEntity verify(ClickKartUserEntity clickKartUser, String rawOtp, Instant now) {
		LoginOtpEntity otp = loginOtpRepository.findOutstanding(clickKartUser)
				.orElseThrow(() -> new InvalidOtpException(GENERIC_REJECTION_MESSAGE));

		if (!otp.isUsable(now)) {
			throw new InvalidOtpException(GENERIC_REJECTION_MESSAGE);
		}

		if (!otp.getOtpHash().equals(jwtService.hashToken(rawOtp))) {
			int attempts = otp.increaseAttempts();
			if (attempts >= authProperties.getOtpMaxVerifyAttempts()) {
				otp.markUsed(now);
			}
			// Persisted via authFailureRecorder (its own REQUIRES_NEW transaction), not
			// directly
			// here - this method is about to throw, and the resulting rollback would
			// otherwise
			// silently undo the attempt-count increment along with it, letting the code be
			// guessed indefinitely within its validity window.
			authFailureRecorder.recordOtpVerifyFailure(otp);
			throw new InvalidOtpException(GENERIC_REJECTION_MESSAGE);
		}

		otp.markUsed(now);
		return otp;
	}
}
