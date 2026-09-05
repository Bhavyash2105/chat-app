package com.nicolas.chatapp.repository;

import com.nicolas.chatapp.model.PreKeyBundle;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PreKeyBundleRepository extends JpaRepository<PreKeyBundle, UUID> {

    /**
     * Fetch a pre-key bundle with a pessimistic write lock so that concurrent
     * consumers of the one-time pre-key pool serialize. This runs inside the
     * service's {@code @Transactional} method, so the row stays locked until
     * the transaction commits after the pool is updated.
     *
     * @param userId the user whose bundle is being consumed from
     * @return the locked bundle, or empty if none exists
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from PreKeyBundle p where p.userId = :userId")
    Optional<PreKeyBundle> findByIdForUpdate(@Param("userId") UUID userId);
}
