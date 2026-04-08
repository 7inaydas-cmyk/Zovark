package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GET /api/v1/entities — list entities for tenant
func listEntitiesHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	entityType := c.Query("type")
	q := c.Query("q")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > 200 {
		limit = 200
	}

	ctx := c.Request.Context()
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "entity list")
		return
	}
	defer tx.Rollback(ctx)

	query := `SELECT id, entity_type, value, threat_score, observation_count,
		confidence, first_seen, last_seen, metadata
		FROM entities WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	argIdx := 2

	if entityType != "" {
		query += ` AND entity_type = $` + strconv.Itoa(argIdx)
		args = append(args, entityType)
		argIdx++
	}
	if q != "" {
		query += ` AND value ILIKE $` + strconv.Itoa(argIdx)
		args = append(args, "%"+q+"%")
		argIdx++
	}

	query += ` ORDER BY last_seen DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		respondInternalError(c, err, "entity query")
		return
	}
	defer rows.Close()

	type Entity struct {
		ID               string                 `json:"id"`
		EntityType       string                 `json:"entity_type"`
		Value            string                 `json:"value"`
		ThreatScore      int                    `json:"threat_score"`
		ObservationCount int                    `json:"observation_count"`
		Confidence       float64                `json:"confidence"`
		FirstSeen        string                 `json:"first_seen"`
		LastSeen         string                 `json:"last_seen"`
		Metadata         map[string]interface{} `json:"metadata"`
	}

	var entities []Entity
	for rows.Next() {
		var e Entity
		var metadata []byte
		err := rows.Scan(&e.ID, &e.EntityType, &e.Value, &e.ThreatScore,
			&e.ObservationCount, &e.Confidence, &e.FirstSeen, &e.LastSeen, &metadata)
		if err != nil {
			continue
		}
		if metadata != nil {
			_ = json.Unmarshal(metadata, &e.Metadata)
		}
		entities = append(entities, e)
	}

	if entities == nil {
		entities = []Entity{}
	}

	// Get total count
	var total int
	countQuery := `SELECT count(*) FROM entities WHERE tenant_id = $1`
	_ = tx.QueryRow(ctx, countQuery, tenantID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"entities": entities,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// GET /api/v1/entities/:id — single entity with edges
func getEntityHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	entityID := c.Param("id")

	ctx := c.Request.Context()
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "entity get")
		return
	}
	defer tx.Rollback(ctx)

	var etype, value string
	var threatScore, obsCount int
	var confidence float64
	var firstSeen, lastSeen string
	err = tx.QueryRow(ctx, `SELECT entity_type, value, threat_score, observation_count,
		confidence, first_seen, last_seen FROM entities
		WHERE id = $1 AND tenant_id = $2`, entityID, tenantID).Scan(
		&etype, &value, &threatScore, &obsCount, &confidence, &firstSeen, &lastSeen)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "entity not found"})
		return
	}

	// Get edges
	type Edge struct {
		ID          string  `json:"id"`
		TargetID    string  `json:"target_id"`
		TargetType  string  `json:"target_type"`
		TargetValue string  `json:"target_value"`
		EdgeType    string  `json:"edge_type"`
		Confidence  float64 `json:"confidence"`
	}
	var edges []Edge

	edgeRows, err := tx.Query(ctx, `
		SELECT ee.id, e2.id, e2.entity_type, e2.value, ee.edge_type, ee.confidence
		FROM entity_edges ee
		JOIN entities e2 ON ee.target_entity_id = e2.id
		WHERE ee.source_entity_id = $1 AND ee.tenant_id = $2
		UNION ALL
		SELECT ee.id, e2.id, e2.entity_type, e2.value, ee.edge_type, ee.confidence
		FROM entity_edges ee
		JOIN entities e2 ON ee.source_entity_id = e2.id
		WHERE ee.target_entity_id = $1 AND ee.tenant_id = $2
	`, entityID, tenantID)
	if err == nil {
		defer edgeRows.Close()
		for edgeRows.Next() {
			var e Edge
			if err := edgeRows.Scan(&e.ID, &e.TargetID, &e.TargetType, &e.TargetValue,
				&e.EdgeType, &e.Confidence); err == nil {
				edges = append(edges, e)
			}
		}
	}
	if edges == nil {
		edges = []Edge{}
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                entityID,
		"entity_type":       etype,
		"value":             value,
		"threat_score":      threatScore,
		"observation_count": obsCount,
		"confidence":        confidence,
		"first_seen":        firstSeen,
		"last_seen":         lastSeen,
		"edges":             edges,
	})
}

// GET /api/v1/entities/:id/graph — graph traversal (depth 1-3)
func entityGraphHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	entityID := c.Param("id")
	depth, _ := strconv.Atoi(c.DefaultQuery("depth", "2"))
	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}

	ctx := c.Request.Context()
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "entity graph")
		return
	}
	defer tx.Rollback(ctx)

	type Node struct {
		ID               string  `json:"id"`
		EntityType       string  `json:"entity_type"`
		Value            string  `json:"value"`
		ThreatScore      int     `json:"threat_score"`
		ObservationCount int     `json:"observation_count"`
		Confidence       float64 `json:"confidence"`
	}
	type EdgeOut struct {
		Source   string  `json:"source"`
		Target   string  `json:"target"`
		EdgeType string  `json:"edge_type"`
		Weight   int     `json:"weight"`
	}

	// Recursive CTE for graph traversal with depth limit
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE graph AS (
			SELECT source_entity_id, target_entity_id, edge_type,
				COALESCE(weight, 1) as weight, 1 as depth
			FROM entity_edges
			WHERE (source_entity_id = $1 OR target_entity_id = $1)
			  AND tenant_id = $2
			UNION
			SELECT ee.source_entity_id, ee.target_entity_id, ee.edge_type,
				COALESCE(ee.weight, 1), g.depth + 1
			FROM entity_edges ee
			JOIN graph g ON (ee.source_entity_id = g.target_entity_id OR ee.target_entity_id = g.source_entity_id)
			WHERE g.depth < $3 AND ee.tenant_id = $2
		)
		SELECT DISTINCT source_entity_id, target_entity_id, edge_type, weight
		FROM graph
		LIMIT 500
	`, entityID, tenantID, depth)
	if err != nil {
		respondInternalError(c, err, "graph traversal")
		return
	}
	defer rows.Close()

	nodeIDs := map[string]bool{entityID: true}
	var edges []EdgeOut
	for rows.Next() {
		var e EdgeOut
		if err := rows.Scan(&e.Source, &e.Target, &e.EdgeType, &e.Weight); err == nil {
			edges = append(edges, e)
			nodeIDs[e.Source] = true
			nodeIDs[e.Target] = true
		}
	}

	// Fetch all referenced nodes
	var nodes []Node
	for nid := range nodeIDs {
		var n Node
		err := tx.QueryRow(ctx, `SELECT id, entity_type, value, threat_score,
			observation_count, confidence FROM entities
			WHERE id = $1 AND tenant_id = $2`, nid, tenantID).Scan(
			&n.ID, &n.EntityType, &n.Value, &n.ThreatScore, &n.ObservationCount, &n.Confidence)
		if err == nil {
			nodes = append(nodes, n)
		}
	}

	if nodes == nil {
		nodes = []Node{}
	}
	if edges == nil {
		edges = []EdgeOut{}
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

// GET /api/v1/entities/search — search by value
func searchEntitiesHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	value := c.Query("value")
	entityType := c.Query("type")

	if value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "value query param required"})
		return
	}

	ctx := c.Request.Context()
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "entity search")
		return
	}
	defer tx.Rollback(ctx)

	query := `SELECT id, entity_type, value, threat_score, observation_count, last_seen
		FROM entities WHERE tenant_id = $1 AND value ILIKE $2`
	args := []interface{}{tenantID, "%" + value + "%"}

	if entityType != "" {
		query += ` AND entity_type = $3`
		args = append(args, entityType)
	}
	query += ` ORDER BY observation_count DESC LIMIT 20`

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		respondInternalError(c, err, "entity search query")
		return
	}
	defer rows.Close()

	type SearchResult struct {
		ID               string `json:"id"`
		EntityType       string `json:"entity_type"`
		Value            string `json:"value"`
		ThreatScore      int    `json:"threat_score"`
		ObservationCount int    `json:"observation_count"`
		LastSeen         string `json:"last_seen"`
	}
	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.ID, &r.EntityType, &r.Value, &r.ThreatScore,
			&r.ObservationCount, &r.LastSeen); err == nil {
			results = append(results, r)
		}
	}
	if results == nil {
		results = []SearchResult{}
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// GET /api/v1/entities/stats — overview statistics
func entityStatsHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	ctx := c.Request.Context()
	tx, err := beginTenantTx(ctx, tenantID)
	if err != nil {
		respondInternalError(c, err, "entity stats")
		return
	}
	defer tx.Rollback(ctx)

	var totalEntities, totalEdges int
	_ = tx.QueryRow(ctx, `SELECT count(*) FROM entities WHERE tenant_id = $1`, tenantID).Scan(&totalEntities)
	_ = tx.QueryRow(ctx, `SELECT count(*) FROM entity_edges WHERE tenant_id = $1`, tenantID).Scan(&totalEdges)

	// Type counts
	type TypeCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	var typeCounts []TypeCount
	typeRows, err := tx.Query(ctx, `SELECT entity_type, count(*) FROM entities
		WHERE tenant_id = $1 GROUP BY entity_type ORDER BY count(*) DESC`, tenantID)
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var tc TypeCount
			if err := typeRows.Scan(&tc.Type, &tc.Count); err == nil {
				typeCounts = append(typeCounts, tc)
			}
		}
	}
	if typeCounts == nil {
		typeCounts = []TypeCount{}
	}

	// Top entities by sighting
	type TopEntity struct {
		Value            string `json:"value"`
		EntityType       string `json:"entity_type"`
		ObservationCount int    `json:"observation_count"`
		ThreatScore      int    `json:"threat_score"`
	}
	var topEntities []TopEntity
	topRows, err := tx.Query(ctx, `SELECT value, entity_type, observation_count, threat_score
		FROM entities WHERE tenant_id = $1 ORDER BY observation_count DESC LIMIT 10`, tenantID)
	if err == nil {
		defer topRows.Close()
		for topRows.Next() {
			var te TopEntity
			if err := topRows.Scan(&te.Value, &te.EntityType, &te.ObservationCount, &te.ThreatScore); err == nil {
				topEntities = append(topEntities, te)
			}
		}
	}
	if topEntities == nil {
		topEntities = []TopEntity{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_entities":     totalEntities,
		"total_edges":        totalEdges,
		"entity_type_counts": typeCounts,
		"top_entities":       topEntities,
	})
}
