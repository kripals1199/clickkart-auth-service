// src/test/java/com/clickkart/auth/serviceimpl/AuditTrailServiceTest.java
package com.clickkart.auth.serviceimpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.clickkart.auth.entity.AuditChainHeadEntity;
import com.clickkart.auth.entity.AuditLogEntryEntity;
import com.clickkart.auth.enums.AuditAction;
import com.clickkart.auth.enums.AuditOutcome;
import com.clickkart.auth.feign.AuditLogServiceClient;
import com.clickkart.auth.repository.AuditChainHeadRepository;
import com.clickkart.auth.repository.AuditLogEntryRepository;
import com.clickkart.auth.service.AuditTrailService;
import com.clickkart.auth.service.ChainIntegrityReport;
import com.clickkart.auth.serviceImpl.AuditTrailServiceImpl;
import com.clickkart.auth.web.RequestMetadata;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuditTrailServiceTest {

    @Mock
    private AuditLogEntryRepository auditLogEntryRepository;

    @Mock
    private AuditChainHeadRepository auditChainHeadRepository;

    @Mock
    private AuditLogServiceClient auditLogServiceClient;

    private AuditTrailService auditTrailService;

    @BeforeEach
    void setUp() {
        auditTrailService = new AuditTrailServiceImpl(auditLogEntryRepository, auditChainHeadRepository, auditLogServiceClient);
    }

    @Test
    void recordLinksNewEntryToCurrentChainHeadAndAdvancesIt() {
        AuditChainHeadEntity head = new AuditChainHeadEntity(AuditTrailService.GENESIS_HASH);
        when(auditChainHeadRepository.lockForUpdate(AuditChainHeadEntity.SINGLETON_ID)).thenReturn(Optional.of(head));

        RequestMetadata metadata = new RequestMetadata("127.0.0.1", "JUnit-Agent");
        auditTrailService.record(
                "cid-1", "USR-abc", AuditAction.LOGIN_SUCCESS, AuditOutcome.SUCCESS, metadata, "some detail");

        ArgumentCaptor<AuditLogEntryEntity> captor = ArgumentCaptor.forClass(AuditLogEntryEntity.class);
        verify(auditLogEntryRepository).save(captor.capture());
        AuditLogEntryEntity saved = captor.getValue();

        assertThat(saved.getPreviousEntryHash()).isEqualTo(AuditTrailService.GENESIS_HASH);
        assertThat(saved.getEntryHash()).isEqualTo(saved.recomputeHash());
        assertThat(head.getLastEntryHash()).isEqualTo(saved.getEntryHash());
        assertThat(head.getEntryCount()).isEqualTo(1L);

        verify(auditLogServiceClient).logEvent(eq("cid-1"), any());
    }

    @Test
    void verifyChainIntegrityPassesOnAnUntamperedChain() {
        AuditLogEntryEntity first = AuditLogEntryEntity.create(
                Instant.now(), "cid-1", "USR-a", AuditAction.REGISTER, AuditOutcome.SUCCESS,
                "127.0.0.1", "agent", null, AuditTrailService.GENESIS_HASH);
        ReflectionTestUtils.setField(first, "id", 1L);

        AuditLogEntryEntity second = AuditLogEntryEntity.create(
                Instant.now(), "cid-2", "USR-a", AuditAction.LOGIN_SUCCESS, AuditOutcome.SUCCESS,
                "127.0.0.1", "agent", null, first.getEntryHash());
        ReflectionTestUtils.setField(second, "id", 2L);

        when(auditLogEntryRepository.findAllByOrderByIdAsc()).thenReturn(List.of(first, second));

        ChainIntegrityReport report = auditTrailService.verifyChainIntegrity();

        assertThat(report.intact()).isTrue();
        assertThat(report.entriesChecked()).isEqualTo(2);
        assertThat(report.brokenAtEntryId()).isNull();
    }

    @Test
    void verifyChainIntegrityDetectsATamperedEntry() {
        AuditLogEntryEntity first = AuditLogEntryEntity.create(
                Instant.now(), "cid-1", "USR-a", AuditAction.REGISTER, AuditOutcome.SUCCESS,
                "127.0.0.1", "agent", null, AuditTrailService.GENESIS_HASH);
        ReflectionTestUtils.setField(first, "id", 1L);

        AuditLogEntryEntity second = AuditLogEntryEntity.create(
                Instant.now(), "cid-2", "USR-a", AuditAction.LOGIN_SUCCESS, AuditOutcome.SUCCESS,
                "127.0.0.1", "agent", null, first.getEntryHash());
        ReflectionTestUtils.setField(second, "id", 2L);

        // Simulate someone editing a historical row directly in the database, bypassing
        // AuditLogEntryEntity.create() - the stored entryHash is now stale relative to the new details.
        ReflectionTestUtils.setField(second, "details", "TAMPERED-VALUE");

        when(auditLogEntryRepository.findAllByOrderByIdAsc()).thenReturn(List.of(first, second));

        ChainIntegrityReport report = auditTrailService.verifyChainIntegrity();

        assertThat(report.intact()).isFalse();
        assertThat(report.entriesChecked()).isEqualTo(2);
        assertThat(report.brokenAtEntryId()).isEqualTo(2L);
    }
}
