package com.sj.audit.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sj.audit.security.ApiKeyAuthFilter;
import com.sj.audit.support.AbstractIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

class AuditApiIT extends AbstractIntegrationTest {

  @Autowired WebApplicationContext context;
  MockMvc mvc;

  @BeforeEach
  void setUpMvc() {
    mvc =
        MockMvcBuilders.webAppContextSetup(context)
            .addFilters(new ApiKeyAuthFilter(properties, JSON))
            .build();
  }

  private static final String EVENT_BODY =
      """
      {"eventType":"USER_LOGIN","actorId":"alice","resourceType":"CLIENT_ACCOUNT",
       "resourceId":"acct-1","payload":{"ip":"10.0.0.1"}}
      """;

  @Test
  void rejectsMissingApiKey() throws Exception {
    mvc.perform(post("/audit/events").contentType(MediaType.APPLICATION_JSON).content(EVENT_BODY))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void rejectsInsufficientScope() throws Exception {
    mvc.perform(
            post("/audit/events")
                .header("X-Api-Key", "test-reader-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(EVENT_BODY))
        .andExpect(status().isForbidden());
  }

  @Test
  void writesAndReadsBackAnEvent() throws Exception {
    mvc.perform(
            post("/audit/events")
                .header("X-Api-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(EVENT_BODY))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.seq").value(1))
        .andExpect(jsonPath("$.contentHash").isNotEmpty())
        .andExpect(jsonPath("$.recordHash").isNotEmpty());

    mvc.perform(get("/audit/events").header("X-Api-Key", "test-reader-key").param("actorId", "alice"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content.length()").value(1))
        .andExpect(jsonPath("$.content[0].actorId").value("alice"));
  }

  @Test
  void filtersOutNonMatchingActors() throws Exception {
    write("alice", "acct-1");
    write("bob", "acct-2");

    mvc.perform(get("/audit/events").header("X-Api-Key", "test-reader-key").param("actorId", "bob"))
        .andExpect(jsonPath("$.content.length()").value(1))
        .andExpect(jsonPath("$.totalElements").value(1));
  }

  @Test
  void paginates() throws Exception {
    for (int i = 0; i < 3; i++) {
      write("alice", "acct-" + i);
    }
    mvc.perform(
            get("/audit/events")
                .header("X-Api-Key", "test-reader-key")
                .param("size", "2")
                .param("page", "0"))
        .andExpect(jsonPath("$.content.length()").value(2))
        .andExpect(jsonPath("$.hasNext").value(true));
  }

  @Test
  void verifyEndpointReportsIntact() throws Exception {
    write("alice", "acct-1");
    mvc.perform(get("/audit/verify").header("X-Api-Key", "test-reader-key"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.intact").value(true));
  }

  @Test
  void hasNoUpdateRoute() throws Exception {
    write("alice", "acct-1");
    mvc.perform(
            put("/audit/events/whatever")
                .header("X-Api-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
        .andExpect(status().isMethodNotAllowed());
  }

  @Test
  void rejectsNonObjectPayload() throws Exception {
    mvc.perform(
            post("/audit/events")
                .header("X-Api-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"eventType\":\"X\",\"actorId\":\"a\",\"resourceType\":\"t\",\"resourceId\":\"r\",\"payload\":\"nope\"}"))
        .andExpect(status().isBadRequest());
  }

  private void write(String actor, String resourceId) throws Exception {
    mvc.perform(
            post("/audit/events")
                .header("X-Api-Key", "test-writer-key")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"eventType":"USER_LOGIN","actorId":"%s","resourceType":"CLIENT_ACCOUNT",
                     "resourceId":"%s","payload":{"ip":"10.0.0.1"}}
                    """
                        .formatted(actor, resourceId)))
        .andExpect(status().isCreated());
  }
}
