// src/main/java/com/clickkart/auth/serviceImpl/AuditTrailServiceImpl.java
package com.clickkart.auth.serviceImpl;

import com.clickkart.auth.entity.AuditChainHeadEntity;
import com.clickkart.auth.entity.AuditLogEntryEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.feign.AuditEventRequest;
import com.clickkart.auth.feign.AuditLogServiceClient;
import com.clickkart.auth.repository.AuditChainHeadRepository;
import com.clickkart.auth.repository.AuditLogEntryRepository;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.ChainIntegrityReport;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class AuditTrailServiceImpl implements AuditTrailService {

	private final AuditLogEntryRepository auditLogEntryRepository;
	private final AuditChainHeadRepository auditChainHeadRepository;
	private final AuditLogServiceClient auditLogServiceClient;

	@Override
	@Transactional(rollbackFor = Exception.class)
	public void record(String correlationId, String actor, AuditAction action, AuditOutcome outcome,RequestMetadata requestMetadata, String details) {
		AuditChainHeadEntity head = auditChainHeadRepository.lockForUpdate(AuditChainHeadEntity.SINGLETON_ID)
				                   .orElseThrow(() -> new IllegalStateException("Audit chain head row missing - AuditChainSeeder should have created it at startup"));

		AuditLogEntryEntity entry = AuditLogEntryEntity.create(Instant.now(), correlationId, actor, action, outcome, requestMetadata.ipAddress(), requestMetadata.userAgent(), details, head.getLastEntryHash());
		auditLogEntryRepository.save(entry);

		head.advance(entry.getEntryHash());
		auditChainHeadRepository.save(head);

		auditLogServiceClient.logEvent(correlationId,AuditEventRequest.of(correlationId, actor, action, requestMetadata.ipAddress(), details));
	}

	/**
	 * O(n) over the whole table; see
	 * {@code AuditLogEntryRepository.findAllByOrderByIdAsc} for the scaling caveat.
	 */
	@Override
	@Transactional(readOnly = true, rollbackFor = Exception.class)
	public ChainIntegrityReport verifyChainIntegrity() {
		
		List<AuditLogEntryEntity> entries = auditLogEntryRepository.findAllByOrderByIdAsc();

		String expectedPreviousHash = GENESIS_HASH;
		for (AuditLogEntryEntity entry : entries) {
			
			if (!expectedPreviousHash.equals(entry.getPreviousEntryHash())) {
				return ChainIntegrityReport.broken(entries.size(), entry.getId(),"previousEntryHash does not match the prior entry's hash - chain link broken");
			}
			
			if (!entry.recomputeHash().equals(entry.getEntryHash())) {
				return ChainIntegrityReport.broken(entries.size(), entry.getId(),"recomputed hash does not match the stored entryHash - entry may have been tampered with");
			}
			
			expectedPreviousHash = entry.getEntryHash();
		}

		return ChainIntegrityReport.intact(entries.size());
	}

	@Override
	@Transactional(readOnly = true, rollbackFor = Exception.class)
	public Page<AuditLogEntryEntity> browse(Pageable pageable) {
		return auditLogEntryRepository.findAllByOrderByIdAsc(pageable);
	}
}
