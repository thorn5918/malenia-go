// Package record 访问记录异步批量落库。
// 对应 malenia 的 backend/AccessRecordCollector + AccessRecordService（实时+批量双写思路）
package record

import (
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"malenia-go/internal/model"
)

// Writer 缓冲式访问记录写入器
type Writer struct {
	db    *gorm.DB
	ch    chan *model.AccessRecord
	wg    sync.WaitGroup
	batch int
}

func NewWriter(db *gorm.DB) *Writer {
	return &Writer{
		db:    db,
		ch:    make(chan *model.AccessRecord, 4096),
		batch: 100,
	}
}

func (w *Writer) Submit(r *model.AccessRecord) {
	select {
	case w.ch <- r:
	default:
		log.Println("[record] channel full, drop record")
	}
}

// Run 启动批量写入循环
func (w *Writer) Run(stop <-chan struct{}) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		buf := make([]*model.AccessRecord, 0, w.batch)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			if err := w.db.Create(&buf).Error; err != nil {
				log.Printf("[record] batch insert failed: %v", err)
			}
			buf = buf[:0]
		}
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				// 排空
				for {
					select {
					case r := <-w.ch:
						buf = append(buf, r)
						if len(buf) >= w.batch {
							flush()
						}
					default:
						flush()
						return
					}
				}
			case r := <-w.ch:
				buf = append(buf, r)
				if len(buf) >= w.batch {
					flush()
				}
			case <-t.C:
				flush()
			}
		}
	}()
}
