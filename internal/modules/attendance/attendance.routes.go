package attendance

import (
	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
)

func RegisterRoutes(router *gin.Engine, handler *Handler, authMiddleware *middleware.AuthMiddleware) {
	// Employee routes (authenticated)
	attendanceGroup := router.Group("/api/v1/attendance")
	attendanceGroup.Use(authMiddleware.Authenticate())
	{
		attendanceGroup.POST("/check-in", handler.CheckIn)
		attendanceGroup.POST("/check-out", handler.CheckOut)
		attendanceGroup.GET("", handler.ListAttendance)
		attendanceGroup.GET("/:id", handler.GetAttendance)
		attendanceGroup.GET("/leave-balance", handler.GetLeaveBalance)
		attendanceGroup.POST("/time-off", handler.RequestTimeOff)
	}

	// Manager routes
	managerGroup := attendanceGroup.Group("")
	managerGroup.Use(authMiddleware.Authorize("manager", "admin"))
	{
		managerGroup.PUT("/:id/manual", handler.ManualAttendance)
		managerGroup.PATCH("/time-off/:id/approve", handler.ApproveTimeOff)
		managerGroup.PATCH("/time-off/:id/reject", handler.RejectTimeOff)
	}

	// Reports (manager/admin)
	reportsGroup := router.Group("/api/v1/reports")
	reportsGroup.Use(authMiddleware.Authenticate(), authMiddleware.Authorize("manager", "admin"))
	{
		reportsGroup.GET("/daily-summary", handler.DailySummary)
		reportsGroup.GET("/employee/:id/export", handler.ExportEmployee)
	}
}
