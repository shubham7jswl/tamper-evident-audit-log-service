package com.sj.audit.api;

import java.util.List;
import org.springframework.data.domain.Page;

/** Minimal, stable pagination envelope (avoids leaking Spring's Page serialization shape). */
public record PageResponse<T>(
    List<T> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext) {

  public static <S, T> PageResponse<T> of(Page<S> page, List<T> mappedContent) {
    return new PageResponse<>(
        mappedContent,
        page.getNumber(),
        page.getSize(),
        page.getTotalElements(),
        page.getTotalPages(),
        page.hasNext());
  }
}
